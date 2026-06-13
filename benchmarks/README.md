# benchmark
This benchmark is performed using vps on DigitalOcean with 4 vps in total within 
the same region. Node running firewall is a "CPU-Optimized" with 2 regular intel vCPUs,
and the other 3 nodes are "CPU-Optimized" with 4 regular intel vCPUs. 
All of the nodes ran Ubuntu 24.04.

The traffic is generated on the 3 vps using a script, 
sending udp packets with 60 bytes as packet size, over 300 seconds.
The firewall is configured to drop all the incoming traffic, 
and the performance is measured by using `node_exporter` to collect 
cpu information.

## baseline
```text
# vps 1
== total ==
total pps:  455168
total Mpps: 0.455
total Mbps: 216.000
total Gbps: 0.216
elapsed:    300.009s
# vps 2
== total ==
total pps:  433678
total Mpps: 0.434
total Mbps: 206.000
total Gbps: 0.206
elapsed:    300.008s
# vps 3
== total ==
total pps:  442634
total Mpps: 0.443
total Mbps: 211.000
total Gbps: 0.211
elapsed:    300.008s

== combined ==
total pps: 1331480
total Mpps: 1.331
total Mbps: 633.000
total Gbps: 0.633
```

## nftables
```text
# vps 1
== total ==
total pps:  454124
total Mpps: 0.454
total Mbps: 216.000
total Gbps: 0.216
elapsed:    300.005s
# vps 2
== total ==
total pps:  442666
total Mpps: 0.443
total Mbps: 211.000
total Gbps: 0.211
elapsed:    300.006s
# vps 3
== total ==
total pps:  433654
total Mpps: 0.434
total Mbps: 205.000
total Gbps: 0.205
elapsed:    300.011s

== combined ==
total pps: 1330444
total Mpps: 1.330
total Mbps: 632.000
total Gbps: 0.632
```

## xdp-guard-rs
```text
# vps 1
== total ==
total pps:  437954
total Mpps: 0.438
total Mbps: 208.000
total Gbps: 0.208
elapsed:    300.010s
# vps 2
== total ==
total pps:  425301
total Mpps: 0.425
total Mbps: 203.000
total Gbps: 0.203
elapsed:    300.006s
# vps 3
== total ==
total pps:  443702
total Mpps: 0.444
total Mbps: 211.000
total Gbps: 0.211
elapsed:    300.010s

== combined ==
total pps: 1306957
total Mpps: 1.307
total Mbps: 622.000
total Gbps: 0.622
```

## Dashboards
![baseline](https://coosisv.cc/xdp-guard-rs-benchmarks/baseline.png)
![nftables](https://coosisv.cc/xdp-guard-rs-benchmarks/nft.png)
![xdp-guard-rs](https://coosisv.cc/xdp-guard-rs-benchmarks/xdp.png)

