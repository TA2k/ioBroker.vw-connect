.class public final synthetic Lsg/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxh/e;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lxh/e;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lsg/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lsg/j;->f:Ljava/lang/String;

    iput-object p2, p0, Lsg/j;->e:Lxh/e;

    return-void
.end method

.method public synthetic constructor <init>(Lxh/e;Ljava/lang/String;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lsg/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lsg/j;->e:Lxh/e;

    iput-object p2, p0, Lsg/j;->f:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lsg/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lhi/a;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$sdkViewModel"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-class v0, Llg/h;

    .line 14
    .line 15
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast p1, Lii/a;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    move-object v2, p1

    .line 28
    check-cast v2, Llg/h;

    .line 29
    .line 30
    new-instance v0, Ljd/b;

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    const/16 v7, 0x19

    .line 34
    .line 35
    const/4 v1, 0x2

    .line 36
    const-class v3, Llg/h;

    .line 37
    .line 38
    const-string v4, "initSubscriptionUpgradeOrFollowUp"

    .line 39
    .line 40
    const-string v5, "initSubscriptionUpgradeOrFollowUp-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 41
    .line 42
    invoke-direct/range {v0 .. v7}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 43
    .line 44
    .line 45
    new-instance v3, Lsg/e;

    .line 46
    .line 47
    iget-object p1, p0, Lsg/j;->f:Ljava/lang/String;

    .line 48
    .line 49
    iget-object p0, p0, Lsg/j;->e:Lxh/e;

    .line 50
    .line 51
    invoke-direct {v3, p1, v0, p0}, Lsg/e;-><init>(Ljava/lang/String;Ljd/b;Lxh/e;)V

    .line 52
    .line 53
    .line 54
    new-instance p0, Lsg/p;

    .line 55
    .line 56
    new-instance v1, Ls60/h;

    .line 57
    .line 58
    const/4 v7, 0x0

    .line 59
    const/16 v8, 0x14

    .line 60
    .line 61
    const/4 v2, 0x1

    .line 62
    const-class v4, Lsg/e;

    .line 63
    .line 64
    const-string v5, "getTariffs"

    .line 65
    .line 66
    const-string v6, "getTariffs-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 67
    .line 68
    invoke-direct/range {v1 .. v8}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 69
    .line 70
    .line 71
    move-object p1, v1

    .line 72
    new-instance v1, Ls60/h;

    .line 73
    .line 74
    const/16 v8, 0x15

    .line 75
    .line 76
    const-class v4, Lsg/e;

    .line 77
    .line 78
    const-string v5, "goToTariffDetails"

    .line 79
    .line 80
    const-string v6, "goToTariffDetails(Lcariad/charging/multicharge/kitten/subscription/models/Tariff;)V"

    .line 81
    .line 82
    invoke-direct/range {v1 .. v8}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 83
    .line 84
    .line 85
    invoke-direct {p0, p1, v1}, Lsg/p;-><init>(Lay0/k;Lay0/k;)V

    .line 86
    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_0
    const-string v0, "$this$sdkViewModel"

    .line 90
    .line 91
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    const-class v0, Llg/h;

    .line 95
    .line 96
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 97
    .line 98
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    check-cast p1, Lii/a;

    .line 103
    .line 104
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    move-object v2, p1

    .line 109
    check-cast v2, Llg/h;

    .line 110
    .line 111
    new-instance v0, Ljd/b;

    .line 112
    .line 113
    const/4 v6, 0x0

    .line 114
    const/16 v7, 0x18

    .line 115
    .line 116
    const/4 v1, 0x2

    .line 117
    const-class v3, Llg/h;

    .line 118
    .line 119
    const-string v4, "initSubscription"

    .line 120
    .line 121
    const-string v5, "initSubscription-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 122
    .line 123
    invoke-direct/range {v0 .. v7}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 124
    .line 125
    .line 126
    new-instance v3, Lsg/b;

    .line 127
    .line 128
    iget-object p1, p0, Lsg/j;->f:Ljava/lang/String;

    .line 129
    .line 130
    iget-object p0, p0, Lsg/j;->e:Lxh/e;

    .line 131
    .line 132
    invoke-direct {v3, p1, v0, p0}, Lsg/b;-><init>(Ljava/lang/String;Ljd/b;Lxh/e;)V

    .line 133
    .line 134
    .line 135
    new-instance p0, Lsg/p;

    .line 136
    .line 137
    new-instance v1, Ls60/h;

    .line 138
    .line 139
    const/4 v7, 0x0

    .line 140
    const/16 v8, 0x12

    .line 141
    .line 142
    const/4 v2, 0x1

    .line 143
    const-class v4, Lsg/b;

    .line 144
    .line 145
    const-string v5, "getTariffs"

    .line 146
    .line 147
    const-string v6, "getTariffs-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 148
    .line 149
    invoke-direct/range {v1 .. v8}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 150
    .line 151
    .line 152
    move-object p1, v1

    .line 153
    new-instance v1, Ls60/h;

    .line 154
    .line 155
    const/16 v8, 0x13

    .line 156
    .line 157
    const-class v4, Lsg/b;

    .line 158
    .line 159
    const-string v5, "goToTariffDetails"

    .line 160
    .line 161
    const-string v6, "goToTariffDetails(Lcariad/charging/multicharge/kitten/subscription/models/Tariff;)V"

    .line 162
    .line 163
    invoke-direct/range {v1 .. v8}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 164
    .line 165
    .line 166
    invoke-direct {p0, p1, v1}, Lsg/p;-><init>(Lay0/k;Lay0/k;)V

    .line 167
    .line 168
    .line 169
    return-object p0

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
