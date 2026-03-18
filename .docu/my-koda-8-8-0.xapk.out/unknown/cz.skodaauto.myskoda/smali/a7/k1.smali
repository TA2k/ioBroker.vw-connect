.class public final La7/k1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Landroid/content/Context;

.field public final synthetic h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, La7/k1;->f:I

    .line 2
    .line 3
    iput-object p1, p0, La7/k1;->g:Landroid/content/Context;

    .line 4
    .line 5
    iput-object p2, p0, La7/k1;->h:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, La7/k1;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La7/k1;->h:Ljava/lang/String;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iget-object p0, p0, La7/k1;->g:Landroid/content/Context;

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, "context.getSharedPrefere\u2026me, Context.MODE_PRIVATE)"

    .line 16
    .line 17
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_0
    iget-object v0, p0, La7/k1;->g:Landroid/content/Context;

    .line 22
    .line 23
    iget-object p0, p0, La7/k1;->h:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {v0, p0}, Ljp/hd;->b(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_1
    iget-object v0, p0, La7/k1;->g:Landroid/content/Context;

    .line 31
    .line 32
    iget-object p0, p0, La7/k1;->h:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, p0}, Llp/ye;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
