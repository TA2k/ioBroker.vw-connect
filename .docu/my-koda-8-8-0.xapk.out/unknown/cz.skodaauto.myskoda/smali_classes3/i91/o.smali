.class public final synthetic Li91/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:I

.field public final synthetic h:Z

.field public final synthetic i:I

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(ILay0/a;Lx2/s;ZII)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li91/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li91/o;->g:I

    iput-object p2, p0, Li91/o;->e:Lay0/a;

    iput-object p3, p0, Li91/o;->f:Lx2/s;

    iput-boolean p4, p0, Li91/o;->h:Z

    iput p5, p0, Li91/o;->i:I

    iput p6, p0, Li91/o;->j:I

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Lx2/s;IZII)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li91/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/o;->e:Lay0/a;

    iput-object p2, p0, Li91/o;->f:Lx2/s;

    iput p3, p0, Li91/o;->g:I

    iput-boolean p4, p0, Li91/o;->h:Z

    iput p5, p0, Li91/o;->i:I

    iput p6, p0, Li91/o;->j:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Li91/o;->d:I

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
    iget p1, p0, Li91/o;->i:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    iget v1, p0, Li91/o;->g:I

    .line 23
    .line 24
    iget v3, p0, Li91/o;->j:I

    .line 25
    .line 26
    iget-object v4, p0, Li91/o;->e:Lay0/a;

    .line 27
    .line 28
    iget-object v6, p0, Li91/o;->f:Lx2/s;

    .line 29
    .line 30
    iget-boolean v7, p0, Li91/o;->h:Z

    .line 31
    .line 32
    invoke-static/range {v1 .. v7}, Li91/j0;->i0(IIILay0/a;Ll2/o;Lx2/s;Z)V

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
    move-object v4, p1

    .line 39
    check-cast v4, Ll2/o;

    .line 40
    .line 41
    check-cast p2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    iget p1, p0, Li91/o;->i:I

    .line 47
    .line 48
    or-int/lit8 p1, p1, 0x1

    .line 49
    .line 50
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    iget v0, p0, Li91/o;->g:I

    .line 55
    .line 56
    iget v2, p0, Li91/o;->j:I

    .line 57
    .line 58
    iget-object v3, p0, Li91/o;->e:Lay0/a;

    .line 59
    .line 60
    iget-object v5, p0, Li91/o;->f:Lx2/s;

    .line 61
    .line 62
    iget-boolean v6, p0, Li91/o;->h:Z

    .line 63
    .line 64
    invoke-static/range {v0 .. v6}, Li91/j0;->j0(IIILay0/a;Ll2/o;Lx2/s;Z)V

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
