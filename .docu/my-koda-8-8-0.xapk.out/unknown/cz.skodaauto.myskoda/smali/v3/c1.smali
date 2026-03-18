.class public final Lv3/c1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lv3/f1;


# direct methods
.method public synthetic constructor <init>(Lv3/f1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lv3/c1;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lv3/c1;->g:Lv3/f1;

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
    .locals 2

    .line 1
    iget v0, p0, Lv3/c1;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lv3/c1;->g:Lv3/f1;

    .line 7
    .line 8
    iget-object p0, p0, Lv3/f1;->t:Lv3/f1;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lv3/f1;->m1()V

    .line 13
    .line 14
    .line 15
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    iget-object p0, p0, Lv3/c1;->g:Lv3/f1;

    .line 19
    .line 20
    iget-object v0, p0, Lv3/f1;->H:Le3/r;

    .line 21
    .line 22
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lv3/f1;->G:Lh3/c;

    .line 26
    .line 27
    invoke-virtual {p0, v0, v1}, Lv3/f1;->Z0(Le3/r;Lh3/c;)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
