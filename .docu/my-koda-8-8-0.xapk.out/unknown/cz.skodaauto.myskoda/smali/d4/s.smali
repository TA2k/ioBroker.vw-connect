.class public final Ld4/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lv3/h0;

.field public final b:Ld4/e;

.field public final c:Landroidx/collection/p;

.field public final d:Landroidx/collection/l0;


# direct methods
.method public constructor <init>(Lv3/h0;Ld4/e;Landroidx/collection/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld4/s;->a:Lv3/h0;

    .line 5
    .line 6
    iput-object p2, p0, Ld4/s;->b:Ld4/e;

    .line 7
    .line 8
    iput-object p3, p0, Ld4/s;->c:Landroidx/collection/p;

    .line 9
    .line 10
    new-instance p1, Landroidx/collection/l0;

    .line 11
    .line 12
    const/4 p2, 0x2

    .line 13
    invoke-direct {p1, p2}, Landroidx/collection/l0;-><init>(I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Ld4/s;->d:Landroidx/collection/l0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()Ld4/q;
    .locals 4

    .line 1
    new-instance v0, Ld4/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ld4/l;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ld4/q;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    iget-object v3, p0, Ld4/s;->b:Ld4/e;

    .line 10
    .line 11
    iget-object p0, p0, Ld4/s;->a:Lv3/h0;

    .line 12
    .line 13
    invoke-direct {v1, v3, v2, p0, v0}, Ld4/q;-><init>(Lx2/r;ZLv3/h0;Ld4/l;)V

    .line 14
    .line 15
    .line 16
    return-object v1
.end method

.method public final b(Lv3/h0;Ld4/l;)V
    .locals 12

    .line 1
    iget-object p0, p0, Ld4/s;->d:Landroidx/collection/l0;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 4
    .line 5
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    move v2, v1

    .line 9
    :goto_0
    if-ge v2, p0, :cond_b

    .line 10
    .line 11
    aget-object v3, v0, v2

    .line 12
    .line 13
    check-cast v3, Ly2/b;

    .line 14
    .line 15
    iget-object v4, v3, Ly2/b;->h:Landroidx/collection/c0;

    .line 16
    .line 17
    iget-object v5, v3, Ly2/b;->c:Lw3/t;

    .line 18
    .line 19
    iget-object v3, v3, Ly2/b;->a:Lpv/g;

    .line 20
    .line 21
    invoke-virtual {p1}, Lv3/h0;->x()Ld4/l;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    iget v7, p1, Lv3/h0;->e:I

    .line 26
    .line 27
    const/4 v8, 0x0

    .line 28
    if-eqz p2, :cond_1

    .line 29
    .line 30
    sget-object v9, Ld4/v;->D:Ld4/z;

    .line 31
    .line 32
    iget-object v10, p2, Ld4/l;->d:Landroidx/collection/q0;

    .line 33
    .line 34
    invoke-virtual {v10, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v9

    .line 38
    if-nez v9, :cond_0

    .line 39
    .line 40
    move-object v9, v8

    .line 41
    :cond_0
    check-cast v9, Lg4/g;

    .line 42
    .line 43
    if-eqz v9, :cond_1

    .line 44
    .line 45
    iget-object v9, v9, Lg4/g;->e:Ljava/lang/String;

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    move-object v9, v8

    .line 49
    :goto_1
    if-eqz v6, :cond_3

    .line 50
    .line 51
    sget-object v10, Ld4/v;->D:Ld4/z;

    .line 52
    .line 53
    iget-object v11, v6, Ld4/l;->d:Landroidx/collection/q0;

    .line 54
    .line 55
    invoke-virtual {v11, v10}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v10

    .line 59
    if-nez v10, :cond_2

    .line 60
    .line 61
    move-object v10, v8

    .line 62
    :cond_2
    check-cast v10, Lg4/g;

    .line 63
    .line 64
    if-eqz v10, :cond_3

    .line 65
    .line 66
    iget-object v8, v10, Lg4/g;->e:Ljava/lang/String;

    .line 67
    .line 68
    :cond_3
    const/4 v10, 0x1

    .line 69
    if-eq v9, v8, :cond_6

    .line 70
    .line 71
    if-nez v9, :cond_4

    .line 72
    .line 73
    invoke-virtual {v3, v5, v7, v10}, Lpv/g;->m(Landroid/view/View;IZ)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    if-nez v8, :cond_5

    .line 78
    .line 79
    invoke-virtual {v3, v5, v7, v1}, Lpv/g;->m(Landroid/view/View;IZ)V

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_5
    sget-object v9, Ld4/v;->r:Ld4/z;

    .line 84
    .line 85
    invoke-static {v6, v9}, Ld4/t;->d(Ld4/l;Ld4/z;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v9

    .line 89
    check-cast v9, Ly2/c;

    .line 90
    .line 91
    sget-object v11, Ly2/i;->a:Ly2/c;

    .line 92
    .line 93
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v9

    .line 97
    if-eqz v9, :cond_6

    .line 98
    .line 99
    invoke-virtual {v8}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v8

    .line 103
    invoke-static {v8}, Landroid/view/autofill/AutofillValue;->forText(Ljava/lang/CharSequence;)Landroid/view/autofill/AutofillValue;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    iget-object v3, v3, Lpv/g;->e:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v3, Landroid/view/autofill/AutofillManager;

    .line 110
    .line 111
    invoke-virtual {v3, v5, v7, v8}, Landroid/view/autofill/AutofillManager;->notifyValueChanged(Landroid/view/View;ILandroid/view/autofill/AutofillValue;)V

    .line 112
    .line 113
    .line 114
    :cond_6
    :goto_2
    if-eqz p2, :cond_7

    .line 115
    .line 116
    iget-object v3, p2, Ld4/l;->d:Landroidx/collection/q0;

    .line 117
    .line 118
    sget-object v5, Ld4/v;->q:Ld4/z;

    .line 119
    .line 120
    invoke-virtual {v3, v5}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    if-ne v3, v10, :cond_7

    .line 125
    .line 126
    move v3, v10

    .line 127
    goto :goto_3

    .line 128
    :cond_7
    move v3, v1

    .line 129
    :goto_3
    if-eqz v6, :cond_8

    .line 130
    .line 131
    iget-object v5, v6, Ld4/l;->d:Landroidx/collection/q0;

    .line 132
    .line 133
    sget-object v6, Ld4/v;->q:Ld4/z;

    .line 134
    .line 135
    invoke-virtual {v5, v6}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    if-ne v5, v10, :cond_8

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_8
    move v10, v1

    .line 143
    :goto_4
    if-eq v3, v10, :cond_a

    .line 144
    .line 145
    if-eqz v10, :cond_9

    .line 146
    .line 147
    invoke-virtual {v4, v7}, Landroidx/collection/c0;->a(I)Z

    .line 148
    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_9
    invoke-virtual {v4, v7}, Landroidx/collection/c0;->e(I)Z

    .line 152
    .line 153
    .line 154
    :cond_a
    :goto_5
    add-int/lit8 v2, v2, 0x1

    .line 155
    .line 156
    goto/16 :goto_0

    .line 157
    .line 158
    :cond_b
    return-void
.end method
