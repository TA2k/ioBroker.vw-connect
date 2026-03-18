.class public final Lx4/b;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx4/r;


# direct methods
.method public synthetic constructor <init>(Lx4/r;I)V
    .locals 0

    .line 1
    iput p2, p0, Lx4/b;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lx4/b;->g:Lx4/r;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lx4/b;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb/a0;

    .line 7
    .line 8
    iget-object p0, p0, Lx4/b;->g:Lx4/r;

    .line 9
    .line 10
    iget-object p1, p0, Lx4/r;->h:Lx4/p;

    .line 11
    .line 12
    iget-boolean p1, p1, Lx4/p;->a:Z

    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lx4/r;->g:Lay0/a;

    .line 17
    .line 18
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 25
    .line 26
    new-instance p1, La2/j;

    .line 27
    .line 28
    const/16 v0, 0x12

    .line 29
    .line 30
    iget-object p0, p0, Lx4/b;->g:Lx4/r;

    .line 31
    .line 32
    invoke-direct {p1, p0, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    return-object p1

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
