.class public final Lw3/p;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lc3/d;


# direct methods
.method public synthetic constructor <init>(Lc3/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw3/p;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lw3/p;->g:Lc3/d;

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
    iget v0, p0, Lw3/p;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lc3/v;

    .line 7
    .line 8
    iget-object p0, p0, Lw3/p;->g:Lc3/d;

    .line 9
    .line 10
    iget p0, p0, Lc3/d;->a:I

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Lc3/v;->b1(I)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    check-cast p1, Lc3/v;

    .line 22
    .line 23
    iget-object p0, p0, Lw3/p;->g:Lc3/d;

    .line 24
    .line 25
    iget p0, p0, Lc3/d;->a:I

    .line 26
    .line 27
    invoke-virtual {p1, p0}, Lc3/v;->b1(I)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
