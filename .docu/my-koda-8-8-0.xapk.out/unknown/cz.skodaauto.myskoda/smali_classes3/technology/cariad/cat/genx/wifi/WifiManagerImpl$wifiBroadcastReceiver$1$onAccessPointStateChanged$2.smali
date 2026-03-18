.class final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;->onAccessPointStateChanged(Landroid/content/Context;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2$WhenMappings;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/n;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Lvy0/b0;",
        "Llx0/b0;",
        "<anonymous>",
        "(Lvy0/b0;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.wifi.WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2"
    f = "WifiManagerImpl.kt"
    l = {
        0x155
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

.field final synthetic this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;Landroid/content/Context;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;",
            "Landroid/content/Context;",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->$context:Landroid/content/Context;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->invokeSuspend$lambda$0$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->invokeSuspend$lambda$0$2(Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->invokeSuspend$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onAccessPointStateChanged(): Access point disabled"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onAccessPointStateChanged(): Access point enabled"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0$2(Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onAccessPointStateChanged(): AccessPointState = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lkotlin/coroutines/Continuation<",
            "*>;)",
            "Lkotlin/coroutines/Continuation<",
            "Llx0/b0;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->$context:Landroid/content/Context;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, p0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;Landroid/content/Context;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$0:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lvy0/b0;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$0:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lvy0/b0;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->label:I

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    if-eqz v3, :cond_1

    .line 13
    .line 14
    if-ne v3, v4, :cond_0

    .line 15
    .line 16
    iget-object v2, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$3:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v2, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 19
    .line 20
    iget-object v3, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$2:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v3, Landroid/content/Context;

    .line 23
    .line 24
    iget-object v0, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$1:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Lez0/a;

    .line 27
    .line 28
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    move-object v5, v3

    .line 32
    move-object v3, v0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw v0

    .line 42
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-object v3, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 46
    .line 47
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;->getMutex()Lez0/a;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    iget-object v5, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->$context:Landroid/content/Context;

    .line 52
    .line 53
    iget-object v6, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 54
    .line 55
    iput-object v1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$0:Ljava/lang/Object;

    .line 56
    .line 57
    iput-object v3, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$1:Ljava/lang/Object;

    .line 58
    .line 59
    iput-object v5, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$2:Ljava/lang/Object;

    .line 60
    .line 61
    iput-object v6, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->L$3:Ljava/lang/Object;

    .line 62
    .line 63
    const/4 v7, 0x0

    .line 64
    iput v7, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->I$0:I

    .line 65
    .line 66
    iput v4, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2;->label:I

    .line 67
    .line 68
    invoke-interface {v3, v0}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    if-ne v0, v2, :cond_2

    .line 73
    .line 74
    return-object v2

    .line 75
    :cond_2
    move-object v2, v6

    .line 76
    :goto_0
    const/4 v6, 0x0

    .line 77
    :try_start_0
    sget-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;

    .line 78
    .line 79
    invoke-virtual {v0, v5}, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState$Companion;->getAccessPointState$genx_release(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-static {v2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->access$get_accessPointState$p(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)Lyy0/j1;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    check-cast v5, Lyy0/c2;

    .line 88
    .line 89
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    check-cast v5, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 94
    .line 95
    if-eq v0, v5, :cond_5

    .line 96
    .line 97
    sget-object v5, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onAccessPointStateChanged$2$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 100
    .line 101
    .line 102
    move-result v7

    .line 103
    aget v5, v5, v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 104
    .line 105
    sget-object v9, Lt51/f;->a:Lt51/f;

    .line 106
    .line 107
    const-string v7, "getName(...)"

    .line 108
    .line 109
    if-eq v5, v4, :cond_4

    .line 110
    .line 111
    const/4 v4, 0x2

    .line 112
    if-eq v5, v4, :cond_3

    .line 113
    .line 114
    :try_start_1
    new-instance v13, Ltechnology/cariad/cat/genx/wifi/m;

    .line 115
    .line 116
    const/4 v4, 0x0

    .line 117
    invoke-direct {v13, v0, v4}, Ltechnology/cariad/cat/genx/wifi/m;-><init>(Ljava/lang/Object;I)V

    .line 118
    .line 119
    .line 120
    const-string v11, "GenX"

    .line 121
    .line 122
    new-instance v10, Lt51/j;

    .line 123
    .line 124
    sget-object v12, Lt51/d;->a:Lt51/d;

    .line 125
    .line 126
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v15

    .line 130
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    invoke-virtual {v1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const/4 v14, 0x0

    .line 142
    move-object/from16 v16, v1

    .line 143
    .line 144
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 148
    .line 149
    .line 150
    goto :goto_1

    .line 151
    :catchall_0
    move-exception v0

    .line 152
    goto :goto_2

    .line 153
    :cond_3
    new-instance v10, Ltechnology/cariad/cat/genx/wifi/i;

    .line 154
    .line 155
    const/4 v4, 0x4

    .line 156
    invoke-direct {v10, v4}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 157
    .line 158
    .line 159
    const-string v8, "GenX"

    .line 160
    .line 161
    new-instance v4, Lt51/j;

    .line 162
    .line 163
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v12

    .line 167
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    invoke-virtual {v1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v13

    .line 175
    invoke-static {v13, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    const/4 v11, 0x0

    .line 179
    move-object v7, v4

    .line 180
    invoke-direct/range {v7 .. v13}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-static {v7}, Lt51/a;->a(Lt51/j;)V

    .line 184
    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_4
    new-instance v10, Ltechnology/cariad/cat/genx/wifi/i;

    .line 188
    .line 189
    const/4 v4, 0x3

    .line 190
    invoke-direct {v10, v4}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 191
    .line 192
    .line 193
    const-string v8, "GenX"

    .line 194
    .line 195
    new-instance v4, Lt51/j;

    .line 196
    .line 197
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v12

    .line 201
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    invoke-virtual {v1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v13

    .line 209
    invoke-static {v13, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    const/4 v11, 0x0

    .line 213
    move-object v7, v4

    .line 214
    invoke-direct/range {v7 .. v13}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    invoke-static {v7}, Lt51/a;->a(Lt51/j;)V

    .line 218
    .line 219
    .line 220
    :goto_1
    invoke-static {v2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->access$get_accessPointState$p(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)Lyy0/j1;

    .line 221
    .line 222
    .line 223
    move-result-object v1

    .line 224
    check-cast v1, Lyy0/c2;

    .line 225
    .line 226
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 227
    .line 228
    .line 229
    invoke-virtual {v1, v6, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 230
    .line 231
    .line 232
    :cond_5
    invoke-interface {v3, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 236
    .line 237
    return-object v0

    .line 238
    :goto_2
    invoke-interface {v3, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 239
    .line 240
    .line 241
    throw v0
.end method
