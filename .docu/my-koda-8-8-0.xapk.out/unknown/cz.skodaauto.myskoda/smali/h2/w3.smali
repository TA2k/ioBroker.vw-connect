.class public final synthetic Lh2/w3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p7, p0, Lh2/w3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/w3;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/w3;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/w3;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lh2/w3;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Lh2/w3;->i:Ljava/lang/Object;

    .line 12
    .line 13
    iput-object p6, p0, Lh2/w3;->j:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lh2/w3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/w3;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Lay0/k;

    .line 10
    .line 11
    iget-object v0, p0, Lh2/w3;->f:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Lay0/k;

    .line 15
    .line 16
    iget-object v0, p0, Lh2/w3;->g:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v4, v0

    .line 19
    check-cast v4, Lay0/k;

    .line 20
    .line 21
    iget-object v0, p0, Lh2/w3;->h:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v5, v0

    .line 24
    check-cast v5, Lay0/k;

    .line 25
    .line 26
    iget-object v0, p0, Lh2/w3;->i:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v6, v0

    .line 29
    check-cast v6, Lay0/k;

    .line 30
    .line 31
    iget-object p0, p0, Lh2/w3;->j:Ljava/lang/Object;

    .line 32
    .line 33
    move-object v7, p0

    .line 34
    check-cast v7, Lay0/k;

    .line 35
    .line 36
    new-instance v1, Luu/v;

    .line 37
    .line 38
    invoke-direct/range {v1 .. v7}, Luu/v;-><init>(Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V

    .line 39
    .line 40
    .line 41
    return-object v1

    .line 42
    :pswitch_0
    iget-object v0, p0, Lh2/w3;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Lu2/b;

    .line 45
    .line 46
    iget-object v1, p0, Lh2/w3;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v1, Lu2/k;

    .line 49
    .line 50
    iget-object v2, p0, Lh2/w3;->g:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v2, Lu2/g;

    .line 53
    .line 54
    iget-object v3, p0, Lh2/w3;->h:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v3, Ljava/lang/String;

    .line 57
    .line 58
    iget-object v4, p0, Lh2/w3;->j:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v4, [Ljava/lang/Object;

    .line 61
    .line 62
    iget-object v5, v0, Lu2/b;->e:Lu2/g;

    .line 63
    .line 64
    const/4 v6, 0x1

    .line 65
    if-eq v5, v2, :cond_0

    .line 66
    .line 67
    iput-object v2, v0, Lu2/b;->e:Lu2/g;

    .line 68
    .line 69
    move v2, v6

    .line 70
    goto :goto_0

    .line 71
    :cond_0
    const/4 v2, 0x0

    .line 72
    :goto_0
    iget-object v5, v0, Lu2/b;->f:Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    if-nez v5, :cond_1

    .line 79
    .line 80
    iput-object v3, v0, Lu2/b;->f:Ljava/lang/String;

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_1
    move v6, v2

    .line 84
    :goto_1
    iput-object v1, v0, Lu2/b;->d:Lu2/k;

    .line 85
    .line 86
    iget-object p0, p0, Lh2/w3;->i:Ljava/lang/Object;

    .line 87
    .line 88
    iput-object p0, v0, Lu2/b;->g:Ljava/lang/Object;

    .line 89
    .line 90
    iput-object v4, v0, Lu2/b;->h:[Ljava/lang/Object;

    .line 91
    .line 92
    iget-object p0, v0, Lu2/b;->i:Lu2/f;

    .line 93
    .line 94
    if-eqz p0, :cond_2

    .line 95
    .line 96
    if-eqz v6, :cond_2

    .line 97
    .line 98
    check-cast p0, Lrn/i;

    .line 99
    .line 100
    invoke-virtual {p0}, Lrn/i;->C()V

    .line 101
    .line 102
    .line 103
    const/4 p0, 0x0

    .line 104
    iput-object p0, v0, Lu2/b;->i:Lu2/f;

    .line 105
    .line 106
    invoke-virtual {v0}, Lu2/b;->a()V

    .line 107
    .line 108
    .line 109
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    return-object p0

    .line 112
    :pswitch_1
    iget-object v0, p0, Lh2/w3;->e:Ljava/lang/Object;

    .line 113
    .line 114
    move-object v2, v0

    .line 115
    check-cast v2, Ljava/lang/Long;

    .line 116
    .line 117
    iget-object v0, p0, Lh2/w3;->f:Ljava/lang/Object;

    .line 118
    .line 119
    move-object v3, v0

    .line 120
    check-cast v3, Ljava/lang/Long;

    .line 121
    .line 122
    iget-object v0, p0, Lh2/w3;->g:Ljava/lang/Object;

    .line 123
    .line 124
    move-object v4, v0

    .line 125
    check-cast v4, Ljava/lang/Long;

    .line 126
    .line 127
    iget-object v0, p0, Lh2/w3;->h:Ljava/lang/Object;

    .line 128
    .line 129
    move-object v5, v0

    .line 130
    check-cast v5, Lgy0/j;

    .line 131
    .line 132
    iget-object v0, p0, Lh2/w3;->i:Ljava/lang/Object;

    .line 133
    .line 134
    move-object v7, v0

    .line 135
    check-cast v7, Lh2/e8;

    .line 136
    .line 137
    iget-object p0, p0, Lh2/w3;->j:Ljava/lang/Object;

    .line 138
    .line 139
    move-object v8, p0

    .line 140
    check-cast v8, Ljava/util/Locale;

    .line 141
    .line 142
    new-instance v1, Lh2/g4;

    .line 143
    .line 144
    const/4 v6, 0x0

    .line 145
    invoke-direct/range {v1 .. v8}, Lh2/g4;-><init>(Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Lgy0/j;ILh2/e8;Ljava/util/Locale;)V

    .line 146
    .line 147
    .line 148
    return-object v1

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
