.class public final synthetic Lpd/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lpd/f0;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lpd/f0;->d:I

    .line 2
    .line 3
    const-string v0, "\', could not start another RPA instance!"

    .line 4
    .line 5
    const-string v1, "startRPA(): failed. An RPA is already running: \'"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    packed-switch p0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance p0, Lrf0/b;

    .line 13
    .line 14
    const-string v0, "true"

    .line 15
    .line 16
    invoke-direct {p0, v0}, Lrf0/b;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    sget-object p0, Lrf0/a;->c:Lrf0/a;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_1
    sget-object p0, Luf/n;->d:Luf/n;

    .line 24
    .line 25
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_2
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_3
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_4
    sget-object p0, Lq7/a;->a:Ll2/e0;

    .line 41
    .line 42
    return-object v2

    .line 43
    :pswitch_5
    sget-object p0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 44
    .line 45
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {p0, v1, v0}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :pswitch_6
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->j()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :pswitch_7
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->q()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_8
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->k()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0

    .line 69
    :pswitch_9
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->o()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_a
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->i()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :pswitch_b
    const-string p0, "dispatchTouchEvent() blocked. deviceDisplayHeightInPx is null!"

    .line 80
    .line 81
    return-object p0

    .line 82
    :pswitch_c
    const-string p0, "dispatchTouchEvent() blocked. deviceDisplayWidthInPx is null!"

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_d
    const-string p0, "SetupDisplaySize(): failed! Could not find an \'Activity\'!"

    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_e
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->n()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :pswitch_f
    sget-object p0, Ltechnology/cariad/cat/remoteparkassist/plugin/RPARunningManager;->b:Lyy0/c2;

    .line 94
    .line 95
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-static {p0, v1, v0}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0

    .line 104
    :pswitch_10
    const-string p0, "startRPA(): RPA is starting..."

    .line 105
    .line 106
    return-object p0

    .line 107
    :pswitch_11
    const-string p0, "onFinish()"

    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_12
    const-string p0, "stopRPAImmediately(): skipped! No RPA instance is currently running!"

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_13
    new-instance p0, Llj0/a;

    .line 114
    .line 115
    const-string v0, "laura_qna_home_send_button"

    .line 116
    .line 117
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_14
    invoke-static {}, Lcz/myskoda/api/bff_common/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    return-object p0

    .line 126
    :pswitch_15
    invoke-static {}, Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;->d()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0

    .line 131
    :pswitch_16
    sget p0, Lpr0/e;->a:F

    .line 132
    .line 133
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    return-object p0

    .line 136
    :pswitch_17
    sget-object p0, Lqe/a;->d:Lqe/a;

    .line 137
    .line 138
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0

    .line 143
    :pswitch_18
    sget-object p0, Lpe/b;->d:Lpe/b;

    .line 144
    .line 145
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    return-object p0

    .line 150
    :pswitch_19
    new-instance p0, Luz0/d;

    .line 151
    .line 152
    sget-object v0, Lpd/c0;->a:Lpd/c0;

    .line 153
    .line 154
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 155
    .line 156
    .line 157
    return-object p0

    .line 158
    :pswitch_1a
    new-instance p0, Luz0/d;

    .line 159
    .line 160
    sget-object v0, Lpd/p0;->a:Lpd/p0;

    .line 161
    .line 162
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 163
    .line 164
    .line 165
    return-object p0

    .line 166
    :pswitch_1b
    new-instance p0, Luz0/d;

    .line 167
    .line 168
    sget-object v0, Lpd/s0;->a:Lpd/s0;

    .line 169
    .line 170
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 171
    .line 172
    .line 173
    return-object p0

    .line 174
    :pswitch_1c
    new-instance p0, Luz0/d;

    .line 175
    .line 176
    sget-object v0, Lpd/j0;->a:Lpd/j0;

    .line 177
    .line 178
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 179
    .line 180
    .line 181
    return-object p0

    .line 182
    nop

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
