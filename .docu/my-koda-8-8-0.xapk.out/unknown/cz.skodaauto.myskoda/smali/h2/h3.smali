.class public final Lh2/h3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ljava/lang/Long;

.field public final synthetic e:J

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Li2/z;

.field public final synthetic i:Lgy0/j;

.field public final synthetic j:Lh2/g2;

.field public final synthetic k:Lh2/e8;

.field public final synthetic l:Lh2/z1;

.field public final synthetic m:Lc3/q;


# direct methods
.method public constructor <init>(Ljava/lang/Long;JLay0/k;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Lc3/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/h3;->d:Ljava/lang/Long;

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/h3;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lh2/h3;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p5, p0, Lh2/h3;->g:Lay0/k;

    .line 11
    .line 12
    iput-object p6, p0, Lh2/h3;->h:Li2/z;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/h3;->i:Lgy0/j;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/h3;->j:Lh2/g2;

    .line 17
    .line 18
    iput-object p9, p0, Lh2/h3;->k:Lh2/e8;

    .line 19
    .line 20
    iput-object p10, p0, Lh2/h3;->l:Lh2/z1;

    .line 21
    .line 22
    iput-object p11, p0, Lh2/h3;->m:Lc3/q;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lb1/n;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Lh2/o4;

    .line 10
    .line 11
    iget v1, v1, Lh2/o4;->a:I

    .line 12
    .line 13
    move-object/from16 v2, p3

    .line 14
    .line 15
    check-cast v2, Ll2/o;

    .line 16
    .line 17
    move-object/from16 v3, p4

    .line 18
    .line 19
    check-cast v3, Ljava/lang/Number;

    .line 20
    .line 21
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 22
    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    move-object v14, v2

    .line 28
    check-cast v14, Ll2/t;

    .line 29
    .line 30
    const v1, 0x5d670292

    .line 31
    .line 32
    .line 33
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 34
    .line 35
    .line 36
    iget-object v13, v0, Lh2/h3;->l:Lh2/z1;

    .line 37
    .line 38
    const/4 v15, 0x0

    .line 39
    iget-object v4, v0, Lh2/h3;->d:Ljava/lang/Long;

    .line 40
    .line 41
    iget-wide v5, v0, Lh2/h3;->e:J

    .line 42
    .line 43
    iget-object v7, v0, Lh2/h3;->f:Lay0/k;

    .line 44
    .line 45
    iget-object v8, v0, Lh2/h3;->g:Lay0/k;

    .line 46
    .line 47
    iget-object v9, v0, Lh2/h3;->h:Li2/z;

    .line 48
    .line 49
    iget-object v10, v0, Lh2/h3;->i:Lgy0/j;

    .line 50
    .line 51
    iget-object v11, v0, Lh2/h3;->j:Lh2/g2;

    .line 52
    .line 53
    iget-object v12, v0, Lh2/h3;->k:Lh2/e8;

    .line 54
    .line 55
    invoke-static/range {v4 .. v15}, Lh2/m3;->c(Ljava/lang/Long;JLay0/k;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Ll2/o;I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    const/4 v4, 0x1

    .line 63
    if-ne v1, v4, :cond_1

    .line 64
    .line 65
    move-object v13, v2

    .line 66
    check-cast v13, Ll2/t;

    .line 67
    .line 68
    const v1, 0x5d674b60

    .line 69
    .line 70
    .line 71
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 72
    .line 73
    .line 74
    iget-object v12, v0, Lh2/h3;->m:Lc3/q;

    .line 75
    .line 76
    const/4 v14, 0x0

    .line 77
    iget-object v5, v0, Lh2/h3;->d:Ljava/lang/Long;

    .line 78
    .line 79
    iget-object v6, v0, Lh2/h3;->f:Lay0/k;

    .line 80
    .line 81
    iget-object v7, v0, Lh2/h3;->h:Li2/z;

    .line 82
    .line 83
    iget-object v8, v0, Lh2/h3;->i:Lgy0/j;

    .line 84
    .line 85
    iget-object v9, v0, Lh2/h3;->j:Lh2/g2;

    .line 86
    .line 87
    iget-object v10, v0, Lh2/h3;->k:Lh2/e8;

    .line 88
    .line 89
    iget-object v11, v0, Lh2/h3;->l:Lh2/z1;

    .line 90
    .line 91
    invoke-static/range {v5 .. v14}, Lh2/x1;->a(Ljava/lang/Long;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Lc3/q;Ll2/o;I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_1
    check-cast v2, Ll2/t;

    .line 99
    .line 100
    const v0, 0x4f88ebe7

    .line 101
    .line 102
    .line 103
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v2, v3}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    return-object v0
.end method
