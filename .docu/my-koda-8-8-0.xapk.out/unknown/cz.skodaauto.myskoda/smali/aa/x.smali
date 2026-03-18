.class public final synthetic Laa/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroid/content/Context;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;I)V
    .locals 0

    .line 1
    iput p2, p0, Laa/x;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laa/x;->e:Landroid/content/Context;

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
    .locals 3

    .line 1
    iget v0, p0, Laa/x;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Ly41/d;->b:Lp6/b;

    .line 7
    .line 8
    sget-object v1, Ly41/d;->a:[Lhy0/z;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    aget-object v1, v1, v2

    .line 12
    .line 13
    iget-object p0, p0, Laa/x;->e:Landroid/content/Context;

    .line 14
    .line 15
    invoke-virtual {v0, p0, v1}, Lp6/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lm6/g;

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_0
    iget-object p0, p0, Laa/x;->e:Landroid/content/Context;

    .line 23
    .line 24
    const-string v0, "firebaseSessions/sessionDataStore.data"

    .line 25
    .line 26
    invoke-static {p0, v0}, Llp/ye;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-static {p0}, Lhu/o;->c(Ljava/io/File;)V

    .line 31
    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_1
    iget-object p0, p0, Laa/x;->e:Landroid/content/Context;

    .line 35
    .line 36
    const-string v0, "firebaseSessions/sessionConfigsDataStore.data"

    .line 37
    .line 38
    invoke-static {p0, v0}, Llp/ye;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-static {p0}, Lhu/o;->c(Ljava/io/File;)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_2
    iget-object p0, p0, Laa/x;->e:Landroid/content/Context;

    .line 47
    .line 48
    invoke-static {p0}, Ljp/t0;->a(Landroid/content/Context;)Lz9/y;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
