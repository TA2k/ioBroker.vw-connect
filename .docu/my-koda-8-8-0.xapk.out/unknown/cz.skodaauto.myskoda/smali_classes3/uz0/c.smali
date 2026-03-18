.class public final Luz0/c;
.super Luz0/n0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I


# direct methods
.method public synthetic constructor <init>(Lsz0/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Luz0/c;->b:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Luz0/n0;-><init>(Lsz0/g;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final h()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Luz0/c;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "kotlin.collections.LinkedHashSet"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "kotlin.collections.HashSet"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "kotlin.collections.ArrayList"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    const-string p0, "kotlin.Array"

    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
