.class public final Lsl/a;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lsl/b;


# direct methods
.method public synthetic constructor <init>(Lsl/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lsl/a;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lsl/a;->g:Lsl/b;

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
    iget v0, p0, Lsl/a;->f:I

    .line 2
    .line 3
    iget-object p0, p0, Lsl/a;->g:Lsl/b;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lsl/b;->f:Ld01/y;

    .line 9
    .line 10
    const-string v0, "Content-Type"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    sget-object v0, Ld01/d0;->e:Lly0/n;

    .line 19
    .line 20
    invoke-static {p0}, Ljp/ue;->e(Ljava/lang/String;)Ld01/d0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    :goto_0
    return-object p0

    .line 27
    :pswitch_0
    sget-object v0, Ld01/h;->n:Ld01/h;

    .line 28
    .line 29
    iget-object p0, p0, Lsl/b;->f:Ld01/y;

    .line 30
    .line 31
    invoke-static {p0}, Ljp/qe;->b(Ld01/y;)Ld01/h;

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
