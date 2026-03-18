.class public final Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg61/e;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0007\u0018\u00002\u00020\u0001\u00a8\u0006\u0002"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;",
        "Lg61/e;",
        "SkodaRemoteParkAssistPlugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lh70/o;Lv51/f;Lh70/d;)V
    .locals 8

    .line 1
    sget-object v0, Lg61/f0;->a:Lg61/v;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v0, Ll71/u;->d:Ll71/d;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    sget-object v0, Ll71/d;->b:Ljava/util/ArrayList;

    .line 12
    .line 13
    new-instance v1, Ljava/util/ArrayList;

    .line 14
    .line 15
    const/16 v2, 0xa

    .line 16
    .line 17
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_3

    .line 33
    .line 34
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Ll71/u;

    .line 39
    .line 40
    const-string v3, "piloPaVersion"

    .line 41
    .line 42
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    sget-object v3, Lg61/v;->b:Ljava/lang/Object;

    .line 46
    .line 47
    invoke-interface {v3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    check-cast v3, Ljava/lang/Iterable;

    .line 52
    .line 53
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    :cond_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    if-eqz v4, :cond_1

    .line 62
    .line 63
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    move-object v5, v4

    .line 68
    check-cast v5, Ljava/util/Map$Entry;

    .line 69
    .line 70
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    if-ne v5, v2, :cond_0

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    const/4 v4, 0x0

    .line 78
    :goto_1
    check-cast v4, Ljava/util/Map$Entry;

    .line 79
    .line 80
    if-eqz v4, :cond_2

    .line 81
    .line 82
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    check-cast v3, Lg61/f0;

    .line 87
    .line 88
    if-eqz v3, :cond_2

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_2
    new-instance v3, Lg61/a0;

    .line 92
    .line 93
    invoke-interface {v2}, Ll71/u;->b()I

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    invoke-interface {v2}, Ll71/u;->a()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    invoke-direct {v3, v4, v2}, Lg61/a0;-><init>(II)V

    .line 102
    .line 103
    .line 104
    :goto_2
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_3
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    new-instance v3, Lg61/d;

    .line 113
    .line 114
    new-instance v1, Ly61/g;

    .line 115
    .line 116
    new-instance v2, Lc71/g;

    .line 117
    .line 118
    invoke-direct {v2, p1}, Lc71/g;-><init>(Landroid/content/Context;)V

    .line 119
    .line 120
    .line 121
    invoke-direct {v1, v2, p3}, Ly61/g;-><init>(Lc71/g;Lh70/o;)V

    .line 122
    .line 123
    .line 124
    invoke-direct {v3, p2, v1, v0}, Lg61/d;-><init>(Ljava/lang/String;Ly61/g;Ljava/util/Set;)V

    .line 125
    .line 126
    .line 127
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 128
    .line 129
    sget-object v6, Lcz0/d;->e:Lcz0/d;

    .line 130
    .line 131
    const-string p2, "ioDispatcher"

    .line 132
    .line 133
    invoke-static {v6, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    new-instance v7, Lk61/b;

    .line 137
    .line 138
    invoke-direct {v7, p1}, Lk61/b;-><init>(Landroid/content/Context;)V

    .line 139
    .line 140
    .line 141
    new-instance v1, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 142
    .line 143
    move-object v2, p1

    .line 144
    move-object v4, p4

    .line 145
    move-object v5, p5

    .line 146
    invoke-direct/range {v1 .. v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;-><init>(Landroid/content/Context;Lg61/d;Lv51/f;Lh70/d;Lvy0/x;Lk61/b;)V

    .line 147
    .line 148
    .line 149
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 150
    .line 151
    .line 152
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 153
    .line 154
    return-void
.end method


# virtual methods
.method public final C()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->C()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final G(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->G(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final J(Lss/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->J(Lss/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final K()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->K()Lyy0/a2;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final O(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->O(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final a0(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->a0(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d0(Ljava/lang/String;Lh61/a;)Lg61/q;
    .locals 1

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->d0(Ljava/lang/String;Lh61/a;)Lg61/q;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final isBluetoothEnabled()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/skodaplugin/SkodaRPAPlugin;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->isBluetoothEnabled()Lyy0/a2;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
