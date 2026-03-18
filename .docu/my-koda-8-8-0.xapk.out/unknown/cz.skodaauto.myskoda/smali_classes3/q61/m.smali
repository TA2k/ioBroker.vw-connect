.class public final synthetic Lq61/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;I)V
    .locals 0

    .line 1
    iput p2, p0, Lq61/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq61/m;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lq61/m;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lq61/m;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    :goto_0
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;->l(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;)F

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    goto :goto_0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
