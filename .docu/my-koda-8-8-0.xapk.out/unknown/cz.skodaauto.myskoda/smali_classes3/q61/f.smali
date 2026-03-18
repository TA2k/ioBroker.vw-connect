.class public final synthetic Lq61/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lq61/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lq61/f;->f:Ll2/b1;

    iput-object p2, p0, Lq61/f;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Ll2/b1;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lq61/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lq61/f;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    iput-object p2, p0, Lq61/f;->f:Ll2/b1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lq61/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lq61/f;->f:Ll2/b1;

    .line 7
    .line 8
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 9
    .line 10
    iget-object p0, p0, Lq61/f;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 11
    .line 12
    invoke-static {v0, p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->j(Ll2/b1;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Landroidx/compose/runtime/DisposableEffectScope;)Ll2/j0;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object v0, p0, Lq61/f;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 18
    .line 19
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 20
    .line 21
    iget-object p0, p0, Lq61/f;->f:Ll2/b1;

    .line 22
    .line 23
    invoke-static {p0, v0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->d(Ll2/b1;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Landroidx/compose/runtime/DisposableEffectScope;)Ll2/j0;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
