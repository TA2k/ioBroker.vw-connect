.class public final synthetic Lq61/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

.field public final synthetic f:Landroid/content/Context;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Landroid/content/Context;II)V
    .locals 0

    .line 1
    iput p4, p0, Lq61/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq61/g;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 4
    .line 5
    iput-object p2, p0, Lq61/g;->f:Landroid/content/Context;

    .line 6
    .line 7
    iput p3, p0, Lq61/g;->g:I

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lq61/g;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lq61/g;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 15
    .line 16
    iget-object v1, p0, Lq61/g;->f:Landroid/content/Context;

    .line 17
    .line 18
    iget p0, p0, Lq61/g;->g:I

    .line 19
    .line 20
    invoke-static {v0, v1, p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->h(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Landroid/content/Context;ILl2/o;I)Llx0/b0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_0
    iget-object v0, p0, Lq61/g;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 26
    .line 27
    iget-object v1, p0, Lq61/g;->f:Landroid/content/Context;

    .line 28
    .line 29
    iget p0, p0, Lq61/g;->g:I

    .line 30
    .line 31
    invoke-static {v0, v1, p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->m(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Landroid/content/Context;ILl2/o;I)Llx0/b0;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    iget-object v0, p0, Lq61/g;->e:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 37
    .line 38
    iget-object v1, p0, Lq61/g;->f:Landroid/content/Context;

    .line 39
    .line 40
    iget p0, p0, Lq61/g;->g:I

    .line 41
    .line 42
    invoke-static {v0, v1, p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->b(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Landroid/content/Context;ILl2/o;I)Llx0/b0;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
