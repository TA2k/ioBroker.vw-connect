.class public final synthetic Ldl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lqb/c;


# direct methods
.method public synthetic constructor <init>(Lqb/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Ldl/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldl/b;->e:Lqb/c;

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
    .locals 4

    .line 1
    iget v0, p0, Ldl/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ldl/b;->e:Lqb/c;

    .line 7
    .line 8
    iget-object p0, p0, Lqb/c;->c:Le/g;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    const-string v0, "android.permission.CAMERA"

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Le/g;->a(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    iget-object p0, p0, Ldl/b;->e:Lqb/c;

    .line 21
    .line 22
    iget-object v0, p0, Lqb/c;->d:Le/g;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, Lqb/c;->a:Landroid/content/Context;

    .line 27
    .line 28
    new-instance v1, Landroid/content/Intent;

    .line 29
    .line 30
    const-string v2, "android.settings.APPLICATION_DETAILS_SETTINGS"

    .line 31
    .line 32
    invoke-direct {v1, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const-string v2, "package"

    .line 36
    .line 37
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    const/4 v3, 0x0

    .line 42
    invoke-static {v2, p0, v3}, Landroid/net/Uri;->fromParts(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {v1, p0}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, v1}, Le/g;->a(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
