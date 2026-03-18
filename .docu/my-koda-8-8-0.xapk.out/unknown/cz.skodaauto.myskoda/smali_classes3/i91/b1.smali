.class public final synthetic Li91/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:I

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;FLgy0/f;IZI)V
    .locals 0

    .line 1
    const/4 p6, 0x1

    iput p6, p0, Li91/b1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/b1;->h:Ljava/lang/Object;

    iput p2, p0, Li91/b1;->e:F

    iput-object p3, p0, Li91/b1;->i:Ljava/lang/Object;

    iput p4, p0, Li91/b1;->f:I

    iput-boolean p5, p0, Li91/b1;->g:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lx2/s;ZFII)V
    .locals 0

    .line 2
    const/4 p5, 0x0

    iput p5, p0, Li91/b1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/b1;->h:Ljava/lang/Object;

    iput-object p2, p0, Li91/b1;->i:Ljava/lang/Object;

    iput-boolean p3, p0, Li91/b1;->g:Z

    iput p4, p0, Li91/b1;->e:F

    iput p6, p0, Li91/b1;->f:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Li91/b1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/b1;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Li91/b1;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Lgy0/f;

    .line 15
    .line 16
    move-object v6, p1

    .line 17
    check-cast v6, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/4 p1, 0x1

    .line 25
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result v7

    .line 29
    iget v2, p0, Li91/b1;->e:F

    .line 30
    .line 31
    iget v4, p0, Li91/b1;->f:I

    .line 32
    .line 33
    iget-boolean v5, p0, Li91/b1;->g:Z

    .line 34
    .line 35
    invoke-static/range {v1 .. v7}, Li91/u3;->e(Ljava/lang/String;FLgy0/f;IZLl2/o;I)V

    .line 36
    .line 37
    .line 38
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    iget-object v0, p0, Li91/b1;->h:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v1, v0

    .line 44
    check-cast v1, Ljava/util/List;

    .line 45
    .line 46
    iget-object v0, p0, Li91/b1;->i:Ljava/lang/Object;

    .line 47
    .line 48
    move-object v2, v0

    .line 49
    check-cast v2, Lx2/s;

    .line 50
    .line 51
    move-object v5, p1

    .line 52
    check-cast v5, Ll2/o;

    .line 53
    .line 54
    check-cast p2, Ljava/lang/Integer;

    .line 55
    .line 56
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    const/4 p1, 0x1

    .line 60
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    iget-boolean v3, p0, Li91/b1;->g:Z

    .line 65
    .line 66
    iget v4, p0, Li91/b1;->e:F

    .line 67
    .line 68
    iget v7, p0, Li91/b1;->f:I

    .line 69
    .line 70
    invoke-static/range {v1 .. v7}, Li91/j0;->F(Ljava/util/List;Lx2/s;ZFLl2/o;II)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
