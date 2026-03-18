.class public final synthetic Lg61/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls61/a;


# direct methods
.method public synthetic constructor <init>(Ls61/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg61/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg61/f;->e:Ls61/a;

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
    iget v0, p0, Lg61/f;->d:I

    .line 2
    .line 3
    const-string v1, "stopRPAImmediately(): currentRPAInstance = "

    .line 4
    .line 5
    const-string v2, "RPA isRunning = "

    .line 6
    .line 7
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const/16 v4, 0xb

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    iget-object p0, p0, Lg61/f;->e:Ls61/a;

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance v0, Lpd/f0;

    .line 18
    .line 19
    invoke-direct {v0, v4}, Lpd/f0;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 26
    .line 27
    invoke-virtual {p0, v5}, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b(Ls61/a;)V

    .line 28
    .line 29
    .line 30
    return-object v3

    .line 31
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 45
    .line 46
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    new-instance v0, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :pswitch_3
    new-instance v0, Lpd/f0;

    .line 71
    .line 72
    invoke-direct {v0, v4}, Lpd/f0;-><init>(I)V

    .line 73
    .line 74
    .line 75
    invoke-static {p0, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 76
    .line 77
    .line 78
    sget-object p0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 79
    .line 80
    invoke-virtual {p0, v5}, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b(Ls61/a;)V

    .line 81
    .line 82
    .line 83
    return-object v3

    .line 84
    :pswitch_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0

    .line 97
    :pswitch_5
    sget-object v0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->a:Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;

    .line 98
    .line 99
    new-instance v0, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    const-string v1, "trackRPAInstance(rpaInstance = "

    .line 102
    .line 103
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string p0, ")"

    .line 110
    .line 111
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
