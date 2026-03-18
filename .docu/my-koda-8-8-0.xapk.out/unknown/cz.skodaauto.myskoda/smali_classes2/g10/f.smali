.class public final Lg10/f;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Le10/d;

.field public final j:Lgn0/f;

.field public final k:Lbh0/g;

.field public final l:Le10/f;

.field public final m:Lbh0/j;

.field public final n:Lbd0/c;

.field public final o:Le10/b;

.field public final p:Lij0/a;

.field public q:Lf10/a;


# direct methods
.method public constructor <init>(Ltr0/b;Le10/d;Lgn0/f;Lbh0/g;Le10/f;Lbh0/j;Lbd0/c;Le10/b;Lij0/a;)V
    .locals 13

    .line 1
    new-instance v0, Lg10/d;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v12, 0x0

    .line 5
    move v2, v1

    .line 6
    const/4 v1, 0x0

    .line 7
    const/16 v3, 0x7ff

    .line 8
    .line 9
    and-int/lit8 v4, v3, 0x8

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    move v4, v5

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v4, v2

    .line 17
    :goto_0
    and-int/lit8 v6, v3, 0x10

    .line 18
    .line 19
    if-eqz v6, :cond_1

    .line 20
    .line 21
    const-string v6, ""

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    const-string v6, "dealerName"

    .line 25
    .line 26
    :goto_1
    and-int/lit8 v7, v3, 0x20

    .line 27
    .line 28
    if-eqz v7, :cond_2

    .line 29
    .line 30
    move-object v7, v1

    .line 31
    goto :goto_2

    .line 32
    :cond_2
    const-string v7, "Jankovcova 1085, 170 00 Praha 7"

    .line 33
    .line 34
    :goto_2
    and-int/lit8 v8, v3, 0x40

    .line 35
    .line 36
    if-eqz v8, :cond_3

    .line 37
    .line 38
    sget-object v8, Lmx0/s;->d:Lmx0/s;

    .line 39
    .line 40
    goto :goto_3

    .line 41
    :cond_3
    move-object v8, v12

    .line 42
    :goto_3
    and-int/lit16 v9, v3, 0x80

    .line 43
    .line 44
    if-eqz v9, :cond_4

    .line 45
    .line 46
    move-object v9, v1

    .line 47
    goto :goto_4

    .line 48
    :cond_4
    const-string v9, "phone"

    .line 49
    .line 50
    :goto_4
    and-int/lit16 v10, v3, 0x100

    .line 51
    .line 52
    if-eqz v10, :cond_5

    .line 53
    .line 54
    move-object v10, v1

    .line 55
    goto :goto_5

    .line 56
    :cond_5
    const-string v10, "website"

    .line 57
    .line 58
    :goto_5
    and-int/lit16 v11, v3, 0x200

    .line 59
    .line 60
    if-eqz v11, :cond_6

    .line 61
    .line 62
    move-object v11, v1

    .line 63
    goto :goto_6

    .line 64
    :cond_6
    const-string v11, "e-mail"

    .line 65
    .line 66
    :goto_6
    and-int/lit16 v3, v3, 0x400

    .line 67
    .line 68
    if-eqz v3, :cond_7

    .line 69
    .line 70
    move v2, v5

    .line 71
    :cond_7
    const/4 v3, 0x0

    .line 72
    move-object v5, v6

    .line 73
    move-object v6, v7

    .line 74
    move-object v7, v8

    .line 75
    move-object v8, v9

    .line 76
    move-object v9, v10

    .line 77
    move-object v10, v11

    .line 78
    move v11, v2

    .line 79
    move v2, v3

    .line 80
    invoke-direct/range {v0 .. v11}, Lg10/d;-><init>(Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 81
    .line 82
    .line 83
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 84
    .line 85
    .line 86
    iput-object p1, p0, Lg10/f;->h:Ltr0/b;

    .line 87
    .line 88
    iput-object p2, p0, Lg10/f;->i:Le10/d;

    .line 89
    .line 90
    move-object/from16 p1, p3

    .line 91
    .line 92
    iput-object p1, p0, Lg10/f;->j:Lgn0/f;

    .line 93
    .line 94
    move-object/from16 p1, p4

    .line 95
    .line 96
    iput-object p1, p0, Lg10/f;->k:Lbh0/g;

    .line 97
    .line 98
    move-object/from16 p1, p5

    .line 99
    .line 100
    iput-object p1, p0, Lg10/f;->l:Le10/f;

    .line 101
    .line 102
    move-object/from16 p1, p6

    .line 103
    .line 104
    iput-object p1, p0, Lg10/f;->m:Lbh0/j;

    .line 105
    .line 106
    move-object/from16 p1, p7

    .line 107
    .line 108
    iput-object p1, p0, Lg10/f;->n:Lbd0/c;

    .line 109
    .line 110
    move-object/from16 p1, p8

    .line 111
    .line 112
    iput-object p1, p0, Lg10/f;->o:Le10/b;

    .line 113
    .line 114
    move-object/from16 p1, p9

    .line 115
    .line 116
    iput-object p1, p0, Lg10/f;->p:Lij0/a;

    .line 117
    .line 118
    new-instance p1, Ldm0/h;

    .line 119
    .line 120
    const/16 v0, 0x16

    .line 121
    .line 122
    invoke-direct {p1, p0, v12, v0}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 126
    .line 127
    .line 128
    return-void
.end method
