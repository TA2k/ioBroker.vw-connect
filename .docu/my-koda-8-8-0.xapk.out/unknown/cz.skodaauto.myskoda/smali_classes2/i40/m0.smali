.class public final synthetic Li40/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/f;

.field public final synthetic f:J

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/f;JLay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li40/m0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/m0;->e:Lh40/f;

    iput-wide p2, p0, Li40/m0;->f:J

    iput-object p4, p0, Li40/m0;->g:Lay0/k;

    iput-object p5, p0, Li40/m0;->h:Lay0/a;

    iput-object p6, p0, Li40/m0;->i:Lay0/a;

    iput-object p7, p0, Li40/m0;->j:Lay0/a;

    iput-object p8, p0, Li40/m0;->k:Lay0/a;

    iput-object p9, p0, Li40/m0;->l:Lay0/a;

    iput-object p10, p0, Li40/m0;->m:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lh40/f;JLay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p11, 0x1

    iput p11, p0, Li40/m0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/m0;->e:Lh40/f;

    iput-wide p2, p0, Li40/m0;->f:J

    iput-object p4, p0, Li40/m0;->g:Lay0/k;

    iput-object p5, p0, Li40/m0;->h:Lay0/a;

    iput-object p6, p0, Li40/m0;->i:Lay0/a;

    iput-object p7, p0, Li40/m0;->j:Lay0/a;

    iput-object p8, p0, Li40/m0;->k:Lay0/a;

    iput-object p9, p0, Li40/m0;->l:Lay0/a;

    iput-object p10, p0, Li40/m0;->m:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Li40/m0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v11, p1

    .line 7
    check-cast v11, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v12

    .line 19
    iget-object v1, p0, Li40/m0;->e:Lh40/f;

    .line 20
    .line 21
    iget-wide v2, p0, Li40/m0;->f:J

    .line 22
    .line 23
    iget-object v4, p0, Li40/m0;->g:Lay0/k;

    .line 24
    .line 25
    iget-object v5, p0, Li40/m0;->h:Lay0/a;

    .line 26
    .line 27
    iget-object v6, p0, Li40/m0;->i:Lay0/a;

    .line 28
    .line 29
    iget-object v7, p0, Li40/m0;->j:Lay0/a;

    .line 30
    .line 31
    iget-object v8, p0, Li40/m0;->k:Lay0/a;

    .line 32
    .line 33
    iget-object v9, p0, Li40/m0;->l:Lay0/a;

    .line 34
    .line 35
    iget-object v10, p0, Li40/m0;->m:Lay0/a;

    .line 36
    .line 37
    invoke-static/range {v1 .. v12}, Li40/o0;->b(Lh40/f;JLay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 44
    .line 45
    check-cast p2, Ljava/lang/Integer;

    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    and-int/lit8 v0, p2, 0x3

    .line 52
    .line 53
    const/4 v1, 0x2

    .line 54
    const/4 v2, 0x1

    .line 55
    if-eq v0, v1, :cond_0

    .line 56
    .line 57
    move v0, v2

    .line 58
    goto :goto_0

    .line 59
    :cond_0
    const/4 v0, 0x0

    .line 60
    :goto_0
    and-int/2addr p2, v2

    .line 61
    move-object v11, p1

    .line 62
    check-cast v11, Ll2/t;

    .line 63
    .line 64
    invoke-virtual {v11, p2, v0}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-eqz p1, :cond_1

    .line 69
    .line 70
    const/4 v12, 0x0

    .line 71
    iget-object v1, p0, Li40/m0;->e:Lh40/f;

    .line 72
    .line 73
    iget-wide v2, p0, Li40/m0;->f:J

    .line 74
    .line 75
    iget-object v4, p0, Li40/m0;->g:Lay0/k;

    .line 76
    .line 77
    iget-object v5, p0, Li40/m0;->h:Lay0/a;

    .line 78
    .line 79
    iget-object v6, p0, Li40/m0;->i:Lay0/a;

    .line 80
    .line 81
    iget-object v7, p0, Li40/m0;->j:Lay0/a;

    .line 82
    .line 83
    iget-object v8, p0, Li40/m0;->k:Lay0/a;

    .line 84
    .line 85
    iget-object v9, p0, Li40/m0;->l:Lay0/a;

    .line 86
    .line 87
    iget-object v10, p0, Li40/m0;->m:Lay0/a;

    .line 88
    .line 89
    invoke-static/range {v1 .. v12}, Li40/o0;->b(Lh40/f;JLay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_1
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 94
    .line 95
    .line 96
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object p0

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
