.class public final Lq61/n;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;I)V
    .locals 0

    .line 1
    iput p2, p0, Lq61/n;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lq61/n;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lq61/n;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lq61/n;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireActivity()Landroidx/fragment/app/o0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Lb/r;->getDefaultViewModelProviderFactory()Landroidx/lifecycle/e1;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Lq61/n;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireActivity()Landroidx/fragment/app/o0;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0}, Lb/r;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object p0, p0, Lq61/n;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 29
    .line 30
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireActivity()Landroidx/fragment/app/o0;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {p0}, Lb/r;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
