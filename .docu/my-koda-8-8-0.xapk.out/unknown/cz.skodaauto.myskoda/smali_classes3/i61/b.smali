.class public final synthetic Li61/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/Set;


# direct methods
.method public synthetic constructor <init>(ILjava/util/Set;)V
    .locals 0

    .line 1
    iput p1, p0, Li61/b;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Li61/b;->e:Ljava/util/Set;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Li61/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Li61/b;->e:Ljava/util/Set;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    const-string v0, "restoreLocalPairingsFromSecureStorage(): Successfully restored "

    .line 13
    .line 14
    const-string v1, " local pairings"

    .line 15
    .line 16
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    iget-object p0, p0, Li61/b;->e:Ljava/util/Set;

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    const-string v0, "storeProviderPairingsInSecureStorage(): Storing "

    .line 28
    .line 29
    const-string v1, " provider pairings"

    .line 30
    .line 31
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    iget-object p0, p0, Li61/b;->e:Ljava/util/Set;

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    const-string v0, "storeLocalPairingsInSecureStorage(): Storing "

    .line 43
    .line 44
    const-string v1, " local pairings"

    .line 45
    .line 46
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :pswitch_2
    iget-object p0, p0, Li61/b;->e:Ljava/util/Set;

    .line 52
    .line 53
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    const-string v0, "restoreProviderPairingsFromSecureStorage(): Successfully restored "

    .line 58
    .line 59
    const-string v1, " local pairings"

    .line 60
    .line 61
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :pswitch_3
    iget-object p0, p0, Li61/b;->e:Ljava/util/Set;

    .line 67
    .line 68
    move-object v0, p0

    .line 69
    check-cast v0, Ljava/lang/Iterable;

    .line 70
    .line 71
    const/4 v4, 0x0

    .line 72
    const/16 v5, 0x39

    .line 73
    .line 74
    const/4 v1, 0x0

    .line 75
    const-string v2, "["

    .line 76
    .line 77
    const-string v3, "]"

    .line 78
    .line 79
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    const-string v0, "setMonitoredBeacons(): These beacons will no longer be monitored = "

    .line 84
    .line 85
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 91
    .line 92
    const-string v1, "pairedVINsCollectJob: pairedVINs = "

    .line 93
    .line 94
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iget-object p0, p0, Li61/b;->e:Ljava/util/Set;

    .line 98
    .line 99
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
