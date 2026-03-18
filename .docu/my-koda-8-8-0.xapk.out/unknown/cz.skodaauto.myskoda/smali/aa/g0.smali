.class public final synthetic Laa/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz9/y;

.field public final synthetic f:Lz9/v;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lx2/e;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Lz9/y;Lz9/v;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;II)V
    .locals 0

    .line 1
    iput p11, p0, Laa/g0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laa/g0;->e:Lz9/y;

    .line 4
    .line 5
    iput-object p2, p0, Laa/g0;->f:Lz9/v;

    .line 6
    .line 7
    iput-object p3, p0, Laa/g0;->g:Lx2/s;

    .line 8
    .line 9
    iput-object p4, p0, Laa/g0;->h:Lx2/e;

    .line 10
    .line 11
    iput-object p5, p0, Laa/g0;->i:Lay0/k;

    .line 12
    .line 13
    iput-object p6, p0, Laa/g0;->j:Lay0/k;

    .line 14
    .line 15
    iput-object p7, p0, Laa/g0;->k:Lay0/k;

    .line 16
    .line 17
    iput-object p8, p0, Laa/g0;->l:Lay0/k;

    .line 18
    .line 19
    iput-object p9, p0, Laa/g0;->m:Lay0/k;

    .line 20
    .line 21
    iput p10, p0, Laa/g0;->n:I

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Laa/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v10, p1

    .line 7
    check-cast v10, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Laa/g0;->n:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v11

    .line 22
    iget-object v1, p0, Laa/g0;->e:Lz9/y;

    .line 23
    .line 24
    iget-object v2, p0, Laa/g0;->f:Lz9/v;

    .line 25
    .line 26
    iget-object v3, p0, Laa/g0;->g:Lx2/s;

    .line 27
    .line 28
    iget-object v4, p0, Laa/g0;->h:Lx2/e;

    .line 29
    .line 30
    iget-object v5, p0, Laa/g0;->i:Lay0/k;

    .line 31
    .line 32
    iget-object v6, p0, Laa/g0;->j:Lay0/k;

    .line 33
    .line 34
    iget-object v7, p0, Laa/g0;->k:Lay0/k;

    .line 35
    .line 36
    iget-object v8, p0, Laa/g0;->l:Lay0/k;

    .line 37
    .line 38
    iget-object v9, p0, Laa/g0;->m:Lay0/k;

    .line 39
    .line 40
    invoke-static/range {v1 .. v11}, Ljp/w0;->c(Lz9/y;Lz9/v;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 41
    .line 42
    .line 43
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_0
    move-object v9, p1

    .line 47
    check-cast v9, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    iget p1, p0, Laa/g0;->n:I

    .line 55
    .line 56
    or-int/lit8 p1, p1, 0x1

    .line 57
    .line 58
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 59
    .line 60
    .line 61
    move-result v10

    .line 62
    iget-object v0, p0, Laa/g0;->e:Lz9/y;

    .line 63
    .line 64
    iget-object v1, p0, Laa/g0;->f:Lz9/v;

    .line 65
    .line 66
    iget-object v2, p0, Laa/g0;->g:Lx2/s;

    .line 67
    .line 68
    iget-object v3, p0, Laa/g0;->h:Lx2/e;

    .line 69
    .line 70
    iget-object v4, p0, Laa/g0;->i:Lay0/k;

    .line 71
    .line 72
    iget-object v5, p0, Laa/g0;->j:Lay0/k;

    .line 73
    .line 74
    iget-object v6, p0, Laa/g0;->k:Lay0/k;

    .line 75
    .line 76
    iget-object v7, p0, Laa/g0;->l:Lay0/k;

    .line 77
    .line 78
    iget-object v8, p0, Laa/g0;->m:Lay0/k;

    .line 79
    .line 80
    invoke-static/range {v0 .. v10}, Ljp/w0;->c(Lz9/y;Lz9/v;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 81
    .line 82
    .line 83
    goto :goto_0

    .line 84
    :pswitch_1
    move-object v9, p1

    .line 85
    check-cast v9, Ll2/o;

    .line 86
    .line 87
    check-cast p2, Ljava/lang/Integer;

    .line 88
    .line 89
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    iget p1, p0, Laa/g0;->n:I

    .line 93
    .line 94
    or-int/lit8 p1, p1, 0x1

    .line 95
    .line 96
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 97
    .line 98
    .line 99
    move-result v10

    .line 100
    iget-object v0, p0, Laa/g0;->e:Lz9/y;

    .line 101
    .line 102
    iget-object v1, p0, Laa/g0;->f:Lz9/v;

    .line 103
    .line 104
    iget-object v2, p0, Laa/g0;->g:Lx2/s;

    .line 105
    .line 106
    iget-object v3, p0, Laa/g0;->h:Lx2/e;

    .line 107
    .line 108
    iget-object v4, p0, Laa/g0;->i:Lay0/k;

    .line 109
    .line 110
    iget-object v5, p0, Laa/g0;->j:Lay0/k;

    .line 111
    .line 112
    iget-object v6, p0, Laa/g0;->k:Lay0/k;

    .line 113
    .line 114
    iget-object v7, p0, Laa/g0;->l:Lay0/k;

    .line 115
    .line 116
    iget-object v8, p0, Laa/g0;->m:Lay0/k;

    .line 117
    .line 118
    invoke-static/range {v0 .. v10}, Ljp/w0;->c(Lz9/y;Lz9/v;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
