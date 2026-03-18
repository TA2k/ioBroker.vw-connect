.class public final synthetic Lh2/x6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li2/g1;


# direct methods
.method public synthetic constructor <init>(Li2/g1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/x6;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/x6;->e:Li2/g1;

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
    .locals 2

    .line 1
    iget v0, p0, Lh2/x6;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget v0, Li2/h1;->d:F

    .line 7
    .line 8
    sget v1, Li2/h1;->e:F

    .line 9
    .line 10
    iget-object p0, p0, Lh2/x6;->e:Li2/g1;

    .line 11
    .line 12
    invoke-virtual {p0}, Li2/g1;->invoke()F

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-static {v0, v1, p0}, Llp/wa;->b(FFF)F

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    new-instance v0, Lt4/f;

    .line 21
    .line 22
    invoke-direct {v0, p0}, Lt4/f;-><init>(F)V

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :pswitch_0
    sget v0, Li2/h1;->d:F

    .line 27
    .line 28
    sget v1, Li2/h1;->e:F

    .line 29
    .line 30
    iget-object p0, p0, Lh2/x6;->e:Li2/g1;

    .line 31
    .line 32
    invoke-virtual {p0}, Li2/g1;->invoke()F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {v0, v1, p0}, Llp/wa;->b(FFF)F

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    new-instance v0, Lt4/f;

    .line 41
    .line 42
    invoke-direct {v0, p0}, Lt4/f;-><init>(F)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
