package vultr

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
	"github.com/vultr/govultr/v3"
	"golang.org/x/oauth2"
)

type Client struct {
	vultr *govultr.Client
	mutex sync.Mutex
}

func (p *Provider) getClient() error {

	config := &oauth2.Config{}
	ts := config.TokenSource(context.TODO(), &oauth2.Token{AccessToken: p.APIToken})

	if p.client.vultr == nil {
		p.client.vultr = govultr.NewClient(oauth2.NewClient(context.TODO(), ts))
	}

	return nil
}

func (p *Provider) getDNSEntries(ctx context.Context, domain string) ([]libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	var records []libdns.Record
	dns_entries, _, _, err := p.client.vultr.DomainRecord.List(ctx, domain, nil)
	if err != nil {
		return records, err
	}

	for _, entry := range dns_entries {
		record, err := libdnsRecord(entry, domain)
		if err != nil {
			return records, err
		}

		records = append(records, record)
	}

	return records, nil
}

func (p *Provider) addDNSRecord(ctx context.Context, domain string, r libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	rr := r.RR()

	req, err := vultrRecordReq(rr)
	if err != nil {
		return nil, err
	}

	vr, _, err := p.client.vultr.DomainRecord.Create(ctx, domain, &req)
	if err != nil {
		return nil, err
	}

	record, err := libdnsRecord(*vr, domain)
	if err != nil {
		return nil, err
	}

	return record, nil
}

func (p *Provider) removeDNSRecord(ctx context.Context, domain string, record libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	id, err := GetRecordID(record)
	if err != nil {
		return nil, err
	}

	err = p.client.vultr.DomainRecord.Delete(ctx, domain, id)
	if err != nil {
		return record, err
	}

	return record, nil
}

func (p *Provider) updateDNSRecord(ctx context.Context, domain string, record libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	id, err := GetRecordID(record)
	if err != nil {
		return record, err
	}

	entry, err := vultrRecordReq(record)
	if err != nil {
		return nil, err
	}

	err = p.client.vultr.DomainRecord.Update(ctx, domain, id, &entry)
	if err != nil {
		return record, err
	}

	return record, nil
}
