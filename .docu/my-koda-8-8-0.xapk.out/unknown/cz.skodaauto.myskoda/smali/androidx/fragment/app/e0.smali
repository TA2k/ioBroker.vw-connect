.class public final Landroidx/fragment/app/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lp/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/fragment/app/e0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/fragment/app/e0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Landroidx/fragment/app/e0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Void;

    .line 7
    .line 8
    iget-object p0, p0, Landroidx/fragment/app/e0;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Le/h;

    .line 11
    .line 12
    return-object p0

    .line 13
    :pswitch_0
    check-cast p1, Ljava/lang/Void;

    .line 14
    .line 15
    iget-object p0, p0, Landroidx/fragment/app/e0;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Landroidx/fragment/app/j0;

    .line 18
    .line 19
    iget-object p1, p0, Landroidx/fragment/app/j0;->mHost:Landroidx/fragment/app/t0;

    .line 20
    .line 21
    instance-of v0, p1, Le/i;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    check-cast p1, Le/i;

    .line 26
    .line 27
    invoke-interface {p1}, Le/i;->getActivityResultRegistry()Le/h;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireActivity()Landroidx/fragment/app/o0;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0}, Lb/r;->getActivityResultRegistry()Le/h;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    :goto_0
    return-object p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
