.class public final synthetic Lhh/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lxh/e;

.field public final synthetic g:Lzb/s0;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lxh/e;Lzb/s0;I)V
    .locals 0

    .line 1
    iput p4, p0, Lhh/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhh/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lhh/a;->f:Lxh/e;

    .line 6
    .line 7
    iput-object p3, p0, Lhh/a;->g:Lzb/s0;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lhh/a;->d:I

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
    const-class v0, Ldh/u;

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
    check-cast v2, Ldh/u;

    .line 29
    .line 30
    new-instance p1, Lih/d;

    .line 31
    .line 32
    new-instance v8, Lai/e;

    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    const/4 v1, 0x7

    .line 36
    iget-object v9, p0, Lhh/a;->e:Ljava/lang/String;

    .line 37
    .line 38
    invoke-direct {v8, v2, v9, v0, v1}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    new-instance v0, Lag/c;

    .line 42
    .line 43
    const/4 v6, 0x0

    .line 44
    const/16 v7, 0x1c

    .line 45
    .line 46
    const/4 v1, 0x2

    .line 47
    const-class v3, Ldh/u;

    .line 48
    .line 49
    const-string v4, "startCharging"

    .line 50
    .line 51
    const-string v5, "startCharging-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/StartChargingSessionRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 52
    .line 53
    invoke-direct/range {v0 .. v7}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 54
    .line 55
    .line 56
    move-object v10, v0

    .line 57
    new-instance v0, Lag/c;

    .line 58
    .line 59
    const/16 v7, 0x1d

    .line 60
    .line 61
    const-class v3, Ldh/u;

    .line 62
    .line 63
    const-string v4, "stopCharging"

    .line 64
    .line 65
    const-string v5, "stopCharging-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/StopChargingSessionRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 66
    .line 67
    invoke-direct/range {v0 .. v7}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 68
    .line 69
    .line 70
    move-object v1, v9

    .line 71
    new-instance v9, Lhh/c;

    .line 72
    .line 73
    const/4 v3, 0x1

    .line 74
    invoke-direct {v9, v2, v1, v3}, Lhh/c;-><init>(Ldh/u;Ljava/lang/String;I)V

    .line 75
    .line 76
    .line 77
    move-object v7, v10

    .line 78
    new-instance v10, Lai/d;

    .line 79
    .line 80
    const/4 v1, 0x2

    .line 81
    invoke-direct {v10, v2, v1}, Lai/d;-><init>(Ldh/u;I)V

    .line 82
    .line 83
    .line 84
    iget-object v5, p0, Lhh/a;->f:Lxh/e;

    .line 85
    .line 86
    iget-object v6, p0, Lhh/a;->g:Lzb/s0;

    .line 87
    .line 88
    move-object v3, p1

    .line 89
    move-object v4, v8

    .line 90
    move-object v8, v0

    .line 91
    invoke-direct/range {v3 .. v10}, Lih/d;-><init>(Lai/e;Lxh/e;Lzb/s0;Lag/c;Lag/c;Lhh/c;Lai/d;)V

    .line 92
    .line 93
    .line 94
    return-object v3

    .line 95
    :pswitch_0
    const-string v0, "$this$sdkViewModel"

    .line 96
    .line 97
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    const-class v0, Ldh/u;

    .line 101
    .line 102
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 103
    .line 104
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    check-cast p1, Lii/a;

    .line 109
    .line 110
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    move-object v2, p1

    .line 115
    check-cast v2, Ldh/u;

    .line 116
    .line 117
    new-instance p1, Lhh/h;

    .line 118
    .line 119
    new-instance v8, Lai/e;

    .line 120
    .line 121
    const/4 v0, 0x0

    .line 122
    const/4 v1, 0x5

    .line 123
    iget-object v9, p0, Lhh/a;->e:Ljava/lang/String;

    .line 124
    .line 125
    invoke-direct {v8, v2, v9, v0, v1}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 126
    .line 127
    .line 128
    new-instance v0, Lag/c;

    .line 129
    .line 130
    const/4 v6, 0x0

    .line 131
    const/16 v7, 0x15

    .line 132
    .line 133
    const/4 v1, 0x2

    .line 134
    const-class v3, Ldh/u;

    .line 135
    .line 136
    const-string v4, "startCharging"

    .line 137
    .line 138
    const-string v5, "startCharging-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/StartChargingSessionRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 139
    .line 140
    invoke-direct/range {v0 .. v7}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 141
    .line 142
    .line 143
    move-object v10, v0

    .line 144
    new-instance v0, Lag/c;

    .line 145
    .line 146
    const/16 v7, 0x16

    .line 147
    .line 148
    const-class v3, Ldh/u;

    .line 149
    .line 150
    const-string v4, "stopCharging"

    .line 151
    .line 152
    const-string v5, "stopCharging-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/StopChargingSessionRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 153
    .line 154
    invoke-direct/range {v0 .. v7}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 155
    .line 156
    .line 157
    move-object v1, v9

    .line 158
    new-instance v9, Lhh/c;

    .line 159
    .line 160
    const/4 v3, 0x0

    .line 161
    invoke-direct {v9, v2, v1, v3}, Lhh/c;-><init>(Ldh/u;Ljava/lang/String;I)V

    .line 162
    .line 163
    .line 164
    move-object v7, v10

    .line 165
    new-instance v10, Lai/d;

    .line 166
    .line 167
    const/4 v1, 0x1

    .line 168
    invoke-direct {v10, v2, v1}, Lai/d;-><init>(Ldh/u;I)V

    .line 169
    .line 170
    .line 171
    iget-object v5, p0, Lhh/a;->f:Lxh/e;

    .line 172
    .line 173
    iget-object v6, p0, Lhh/a;->g:Lzb/s0;

    .line 174
    .line 175
    move-object v3, p1

    .line 176
    move-object v4, v8

    .line 177
    move-object v8, v0

    .line 178
    invoke-direct/range {v3 .. v10}, Lhh/h;-><init>(Lai/e;Lxh/e;Lzb/s0;Lag/c;Lag/c;Lhh/c;Lai/d;)V

    .line 179
    .line 180
    .line 181
    return-object v3

    .line 182
    nop

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
