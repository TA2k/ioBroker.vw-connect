.class public final Lkn/e0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ll2/b1;


# direct methods
.method public constructor <init>(Ll2/b1;I)V
    .locals 1

    .line 1
    iput p2, p0, Lkn/e0;->f:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    packed-switch p2, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    sget-object p2, Lkn/f0;->d:Lkn/f0;

    .line 8
    .line 9
    iput-object p1, p0, Lkn/e0;->g:Ll2/b1;

    .line 10
    .line 11
    invoke-direct {p0, v0}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    iput-object p1, p0, Lkn/e0;->g:Ll2/b1;

    .line 16
    .line 17
    invoke-direct {p0, v0}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lkn/e0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkn/e0;->g:Ll2/b1;

    .line 7
    .line 8
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ld3/b;

    .line 13
    .line 14
    iget-wide v0, p0, Ld3/b;->a:J

    .line 15
    .line 16
    new-instance p0, Ld3/b;

    .line 17
    .line 18
    invoke-direct {p0, v0, v1}, Ld3/b;-><init>(J)V

    .line 19
    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_0
    new-instance v0, Lkn/c0;

    .line 23
    .line 24
    sget-object v1, Lkn/f0;->f:Lkn/f0;

    .line 25
    .line 26
    iget-object p0, p0, Lkn/e0;->g:Ll2/b1;

    .line 27
    .line 28
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Lay0/k;

    .line 33
    .line 34
    invoke-direct {v0, v1, p0}, Lkn/c0;-><init>(Lkn/f0;Lay0/k;)V

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
