.class public final synthetic Lqb/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lqb/c;


# direct methods
.method public synthetic constructor <init>(Lqb/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Lqb/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqb/b;->e:Lqb/c;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lqb/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Le/a;

    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lqb/b;->e:Lqb/c;

    .line 14
    .line 15
    iget-object p1, p0, Lqb/c;->a:Landroid/content/Context;

    .line 16
    .line 17
    const-string v0, "android.permission.CAMERA"

    .line 18
    .line 19
    invoke-static {p1, v0}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-nez p1, :cond_0

    .line 24
    .line 25
    const/4 p1, 0x1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p1, 0x0

    .line 28
    :goto_0
    iget-object p0, p0, Lqb/c;->b:Lyy0/c2;

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    sget-object p1, Lqb/d;->c:Lqb/d;

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    sget-object p1, Lqb/d;->b:Lqb/d;

    .line 36
    .line 37
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    iget-object p0, p0, Lqb/b;->e:Lqb/c;

    .line 52
    .line 53
    iget-object p0, p0, Lqb/c;->b:Lyy0/c2;

    .line 54
    .line 55
    if-eqz p1, :cond_2

    .line 56
    .line 57
    sget-object p1, Lqb/d;->c:Lqb/d;

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    sget-object p1, Lqb/d;->a:Lqb/d;

    .line 61
    .line 62
    :goto_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    const/4 v0, 0x0

    .line 66
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
