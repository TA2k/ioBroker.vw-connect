.class public final synthetic Lg1/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lkotlin/jvm/internal/c0;


# direct methods
.method public synthetic constructor <init>(Lkotlin/jvm/internal/c0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg1/r0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg1/r0;->e:Lkotlin/jvm/internal/c0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/r0;->d:I

    .line 2
    .line 3
    check-cast p1, Lp3/t;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Float;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Lp3/t;->a()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lg1/r0;->e:Lkotlin/jvm/internal/c0;

    .line 18
    .line 19
    iput p2, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 20
    .line 21
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    invoke-virtual {p1}, Lp3/t;->a()V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lg1/r0;->e:Lkotlin/jvm/internal/c0;

    .line 28
    .line 29
    iput p2, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :pswitch_1
    invoke-virtual {p1}, Lp3/t;->a()V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lg1/r0;->e:Lkotlin/jvm/internal/c0;

    .line 36
    .line 37
    iput p2, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 38
    .line 39
    goto :goto_0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
