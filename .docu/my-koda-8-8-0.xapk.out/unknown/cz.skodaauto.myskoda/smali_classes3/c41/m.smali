.class public final synthetic Lc41/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Li31/e;

.field public final synthetic g:I

.field public final synthetic h:Lp31/f;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Li31/e;ILp31/f;I)V
    .locals 0

    .line 1
    iput p5, p0, Lc41/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc41/m;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lc41/m;->f:Li31/e;

    .line 6
    .line 7
    iput p3, p0, Lc41/m;->g:I

    .line 8
    .line 9
    iput-object p4, p0, Lc41/m;->h:Lp31/f;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lc41/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lx31/b;

    .line 7
    .line 8
    iget-object v1, p0, Lc41/m;->h:Lp31/f;

    .line 9
    .line 10
    iget-boolean v1, v1, Lp31/f;->b:Z

    .line 11
    .line 12
    xor-int/lit8 v1, v1, 0x1

    .line 13
    .line 14
    iget-object v2, p0, Lc41/m;->f:Li31/e;

    .line 15
    .line 16
    iget v3, p0, Lc41/m;->g:I

    .line 17
    .line 18
    invoke-direct {v0, v2, v3, v1}, Lx31/b;-><init>(Li31/e;IZ)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lc41/m;->e:Lay0/k;

    .line 22
    .line 23
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lx31/b;

    .line 30
    .line 31
    iget-object v1, p0, Lc41/m;->h:Lp31/f;

    .line 32
    .line 33
    iget-boolean v1, v1, Lp31/f;->b:Z

    .line 34
    .line 35
    xor-int/lit8 v1, v1, 0x1

    .line 36
    .line 37
    iget-object v2, p0, Lc41/m;->f:Li31/e;

    .line 38
    .line 39
    iget v3, p0, Lc41/m;->g:I

    .line 40
    .line 41
    invoke-direct {v0, v2, v3, v1}, Lx31/b;-><init>(Li31/e;IZ)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lc41/m;->e:Lay0/k;

    .line 45
    .line 46
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
