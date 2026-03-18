.class public final synthetic Lyl/k;
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
    iput p1, p0, Lyl/k;->d:I

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
    .locals 6

    .line 1
    iget p0, p0, Lyl/k;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    packed-switch p0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    sget-object p0, Lsm/g;->b:Llx0/q;

    .line 8
    .line 9
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/util/List;

    .line 14
    .line 15
    check-cast p0, Ljava/lang/Iterable;

    .line 16
    .line 17
    new-instance v1, Lyl/s;

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-direct {v1, v2}, Lyl/s;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0, v1}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    new-instance v1, Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 30
    .line 31
    .line 32
    move-object v2, p0

    .line 33
    check-cast v2, Ljava/util/Collection;

    .line 34
    .line 35
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    :goto_0
    if-ge v0, v2, :cond_0

    .line 40
    .line 41
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    check-cast v3, Lpm/b;

    .line 46
    .line 47
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    new-instance v3, Lom/e;

    .line 51
    .line 52
    invoke-direct {v3}, Lom/e;-><init>()V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    add-int/lit8 v0, v0, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    return-object v1

    .line 62
    :pswitch_0
    sget-object p0, Lsm/g;->a:Llx0/q;

    .line 63
    .line 64
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    check-cast p0, Ljava/util/List;

    .line 69
    .line 70
    check-cast p0, Ljava/lang/Iterable;

    .line 71
    .line 72
    new-instance v1, Lyl/s;

    .line 73
    .line 74
    invoke-direct {v1, v0}, Lyl/s;-><init>(I)V

    .line 75
    .line 76
    .line 77
    invoke-static {p0, v1}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    new-instance v1, Ljava/util/ArrayList;

    .line 82
    .line 83
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 84
    .line 85
    .line 86
    move-object v2, p0

    .line 87
    check-cast v2, Ljava/util/Collection;

    .line 88
    .line 89
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    :goto_1
    if-ge v0, v2, :cond_3

    .line 94
    .line 95
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Llm/d;

    .line 100
    .line 101
    const-string v4, "null cannot be cast to non-null type coil3.util.FetcherServiceLoaderTarget<kotlin.Any>"

    .line 102
    .line 103
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    new-instance v3, Lim/j;

    .line 107
    .line 108
    new-instance v4, Ljv0/c;

    .line 109
    .line 110
    const/16 v5, 0x17

    .line 111
    .line 112
    invoke-direct {v4, v5}, Ljv0/c;-><init>(I)V

    .line 113
    .line 114
    .line 115
    invoke-direct {v3, v4}, Lim/j;-><init>(Lay0/a;)V

    .line 116
    .line 117
    .line 118
    const-class v4, Lyl/t;

    .line 119
    .line 120
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 121
    .line 122
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    if-nez v4, :cond_1

    .line 127
    .line 128
    const/4 v3, 0x0

    .line 129
    goto :goto_2

    .line 130
    :cond_1
    new-instance v5, Llx0/l;

    .line 131
    .line 132
    invoke-direct {v5, v3, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    move-object v3, v5

    .line 136
    :goto_2
    if-eqz v3, :cond_2

    .line 137
    .line 138
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 142
    .line 143
    goto :goto_1

    .line 144
    :cond_3
    return-object v1

    .line 145
    :pswitch_1
    sget-object p0, Lcm/h;->a:Llx0/q;

    .line 146
    .line 147
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    check-cast p0, Lcm/g;

    .line 152
    .line 153
    return-object p0

    .line 154
    :pswitch_2
    sget-object p0, Lvy0/p0;->a:Lcz0/e;

    .line 155
    .line 156
    sget-object p0, Laz0/m;->a:Lwy0/c;

    .line 157
    .line 158
    iget-object p0, p0, Lwy0/c;->h:Lwy0/c;

    .line 159
    .line 160
    return-object p0

    .line 161
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
