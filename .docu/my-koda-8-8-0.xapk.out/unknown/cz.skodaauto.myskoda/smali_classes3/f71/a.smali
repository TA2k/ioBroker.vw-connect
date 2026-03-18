.class public final synthetic Lf71/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lh40/u;Lay0/a;ZZI)V
    .locals 0

    .line 1
    const/4 p6, 0x1

    iput p6, p0, Lf71/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf71/a;->e:Lx2/s;

    iput-object p2, p0, Lf71/a;->i:Ljava/lang/Object;

    iput-object p3, p0, Lf71/a;->f:Lay0/a;

    iput-boolean p4, p0, Lf71/a;->g:Z

    iput-boolean p5, p0, Lf71/a;->h:Z

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ZZLay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p6, 0x0

    iput p6, p0, Lf71/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf71/a;->e:Lx2/s;

    iput-boolean p2, p0, Lf71/a;->g:Z

    iput-boolean p3, p0, Lf71/a;->h:Z

    iput-object p4, p0, Lf71/a;->f:Lay0/a;

    iput-object p5, p0, Lf71/a;->i:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lf71/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lf71/a;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Lh40/u;

    .line 10
    .line 11
    move-object v6, p1

    .line 12
    check-cast v6, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v7

    .line 24
    iget-object v1, p0, Lf71/a;->e:Lx2/s;

    .line 25
    .line 26
    iget-object v3, p0, Lf71/a;->f:Lay0/a;

    .line 27
    .line 28
    iget-boolean v4, p0, Lf71/a;->g:Z

    .line 29
    .line 30
    iget-boolean v5, p0, Lf71/a;->h:Z

    .line 31
    .line 32
    invoke-static/range {v1 .. v7}, Li40/q;->i(Lx2/s;Lh40/u;Lay0/a;ZZLl2/o;I)V

    .line 33
    .line 34
    .line 35
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    iget-object v0, p0, Lf71/a;->i:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v5, v0

    .line 41
    check-cast v5, Lay0/a;

    .line 42
    .line 43
    move-object v6, p1

    .line 44
    check-cast v6, Ll2/o;

    .line 45
    .line 46
    check-cast p2, Ljava/lang/Integer;

    .line 47
    .line 48
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    const/4 p1, 0x1

    .line 52
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 53
    .line 54
    .line 55
    move-result v7

    .line 56
    iget-object v1, p0, Lf71/a;->e:Lx2/s;

    .line 57
    .line 58
    iget-boolean v2, p0, Lf71/a;->g:Z

    .line 59
    .line 60
    iget-boolean v3, p0, Lf71/a;->h:Z

    .line 61
    .line 62
    iget-object v4, p0, Lf71/a;->f:Lay0/a;

    .line 63
    .line 64
    invoke-static/range {v1 .. v7}, Lkp/q7;->a(Lx2/s;ZZLay0/a;Lay0/a;Ll2/o;I)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
