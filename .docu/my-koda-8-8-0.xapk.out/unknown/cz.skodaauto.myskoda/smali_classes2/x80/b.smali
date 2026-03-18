.class public final synthetic Lx80/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw80/d;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lw80/d;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    iput p13, p0, Lx80/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lx80/b;->e:Lw80/d;

    .line 4
    .line 5
    iput-object p2, p0, Lx80/b;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Lx80/b;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Lx80/b;->h:Lay0/k;

    .line 10
    .line 11
    iput-object p5, p0, Lx80/b;->i:Lay0/a;

    .line 12
    .line 13
    iput-object p6, p0, Lx80/b;->j:Lay0/a;

    .line 14
    .line 15
    iput-object p7, p0, Lx80/b;->k:Lay0/a;

    .line 16
    .line 17
    iput-object p8, p0, Lx80/b;->l:Lay0/a;

    .line 18
    .line 19
    iput-object p9, p0, Lx80/b;->m:Lay0/k;

    .line 20
    .line 21
    iput-object p10, p0, Lx80/b;->n:Lay0/a;

    .line 22
    .line 23
    iput-object p11, p0, Lx80/b;->o:Lay0/a;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lx80/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v12, p1

    .line 7
    check-cast v12, Ll2/o;

    .line 8
    .line 9
    move-object/from16 v0, p2

    .line 10
    .line 11
    check-cast v0, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result v13

    .line 21
    iget-object v1, p0, Lx80/b;->e:Lw80/d;

    .line 22
    .line 23
    iget-object v2, p0, Lx80/b;->f:Lay0/a;

    .line 24
    .line 25
    iget-object v3, p0, Lx80/b;->g:Lay0/a;

    .line 26
    .line 27
    iget-object v4, p0, Lx80/b;->h:Lay0/k;

    .line 28
    .line 29
    iget-object v5, p0, Lx80/b;->i:Lay0/a;

    .line 30
    .line 31
    iget-object v6, p0, Lx80/b;->j:Lay0/a;

    .line 32
    .line 33
    iget-object v7, p0, Lx80/b;->k:Lay0/a;

    .line 34
    .line 35
    iget-object v8, p0, Lx80/b;->l:Lay0/a;

    .line 36
    .line 37
    iget-object v9, p0, Lx80/b;->m:Lay0/k;

    .line 38
    .line 39
    iget-object v10, p0, Lx80/b;->n:Lay0/a;

    .line 40
    .line 41
    iget-object v11, p0, Lx80/b;->o:Lay0/a;

    .line 42
    .line 43
    invoke-static/range {v1 .. v13}, Lx80/d;->e(Lw80/d;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 44
    .line 45
    .line 46
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_0
    move-object v11, p1

    .line 50
    check-cast v11, Ll2/o;

    .line 51
    .line 52
    move-object/from16 v0, p2

    .line 53
    .line 54
    check-cast v0, Ljava/lang/Integer;

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    const/4 v0, 0x1

    .line 60
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 61
    .line 62
    .line 63
    move-result v12

    .line 64
    iget-object v0, p0, Lx80/b;->e:Lw80/d;

    .line 65
    .line 66
    iget-object v1, p0, Lx80/b;->f:Lay0/a;

    .line 67
    .line 68
    iget-object v2, p0, Lx80/b;->g:Lay0/a;

    .line 69
    .line 70
    iget-object v3, p0, Lx80/b;->h:Lay0/k;

    .line 71
    .line 72
    iget-object v4, p0, Lx80/b;->i:Lay0/a;

    .line 73
    .line 74
    iget-object v5, p0, Lx80/b;->j:Lay0/a;

    .line 75
    .line 76
    iget-object v6, p0, Lx80/b;->k:Lay0/a;

    .line 77
    .line 78
    iget-object v7, p0, Lx80/b;->l:Lay0/a;

    .line 79
    .line 80
    iget-object v8, p0, Lx80/b;->m:Lay0/k;

    .line 81
    .line 82
    iget-object v9, p0, Lx80/b;->n:Lay0/a;

    .line 83
    .line 84
    iget-object v10, p0, Lx80/b;->o:Lay0/a;

    .line 85
    .line 86
    invoke-static/range {v0 .. v12}, Lx80/d;->e(Lw80/d;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
