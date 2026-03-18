.class public final synthetic Lz61/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/util/Set;

.field public final synthetic g:Ljava/util/Set;

.field public final synthetic h:Z

.field public final synthetic i:Ls71/k;

.field public final synthetic j:Z

.field public final synthetic k:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/util/Set;Ljava/util/Set;ZLs71/k;Lay0/k;ZI)V
    .locals 0

    .line 1
    const/4 p8, 0x0

    iput p8, p0, Lz61/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lz61/i;->e:Lx2/s;

    iput-object p2, p0, Lz61/i;->f:Ljava/util/Set;

    iput-object p3, p0, Lz61/i;->g:Ljava/util/Set;

    iput-boolean p4, p0, Lz61/i;->h:Z

    iput-object p5, p0, Lz61/i;->i:Ls71/k;

    iput-object p6, p0, Lz61/i;->k:Lay0/k;

    iput-boolean p7, p0, Lz61/i;->j:Z

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/util/Set;Ljava/util/Set;ZLs71/k;ZLay0/k;I)V
    .locals 0

    .line 2
    const/4 p8, 0x1

    iput p8, p0, Lz61/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lz61/i;->e:Lx2/s;

    iput-object p2, p0, Lz61/i;->f:Ljava/util/Set;

    iput-object p3, p0, Lz61/i;->g:Ljava/util/Set;

    iput-boolean p4, p0, Lz61/i;->h:Z

    iput-object p5, p0, Lz61/i;->i:Ls71/k;

    iput-boolean p6, p0, Lz61/i;->j:Z

    iput-object p7, p0, Lz61/i;->k:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lz61/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x7

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget-object v2, p0, Lz61/i;->k:Lay0/k;

    .line 20
    .line 21
    iget-object v3, p0, Lz61/i;->f:Ljava/util/Set;

    .line 22
    .line 23
    iget-object v4, p0, Lz61/i;->g:Ljava/util/Set;

    .line 24
    .line 25
    iget-object v6, p0, Lz61/i;->i:Ls71/k;

    .line 26
    .line 27
    iget-object v7, p0, Lz61/i;->e:Lx2/s;

    .line 28
    .line 29
    iget-boolean v8, p0, Lz61/i;->h:Z

    .line 30
    .line 31
    iget-boolean v9, p0, Lz61/i;->j:Z

    .line 32
    .line 33
    invoke-static/range {v1 .. v9}, Lz61/a;->o(ILay0/k;Ljava/util/Set;Ljava/util/Set;Ll2/o;Ls71/k;Lx2/s;ZZ)V

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    move-object v4, p1

    .line 40
    check-cast v4, Ll2/o;

    .line 41
    .line 42
    check-cast p2, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    const/4 p1, 0x1

    .line 48
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object v1, p0, Lz61/i;->k:Lay0/k;

    .line 53
    .line 54
    iget-object v2, p0, Lz61/i;->f:Ljava/util/Set;

    .line 55
    .line 56
    iget-object v3, p0, Lz61/i;->g:Ljava/util/Set;

    .line 57
    .line 58
    iget-object v5, p0, Lz61/i;->i:Ls71/k;

    .line 59
    .line 60
    iget-object v6, p0, Lz61/i;->e:Lx2/s;

    .line 61
    .line 62
    iget-boolean v7, p0, Lz61/i;->h:Z

    .line 63
    .line 64
    iget-boolean v8, p0, Lz61/i;->j:Z

    .line 65
    .line 66
    invoke-static/range {v0 .. v8}, Lz61/a;->k(ILay0/k;Ljava/util/Set;Ljava/util/Set;Ll2/o;Ls71/k;Lx2/s;ZZ)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
