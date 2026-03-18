.class public final synthetic Lu1/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Landroid/content/Context;

    .line 2
    .line 3
    check-cast p2, Landroid/content/pm/ResolveInfo;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Boolean;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    check-cast p4, Ljava/lang/CharSequence;

    .line 12
    .line 13
    check-cast p5, Lg4/o0;

    .line 14
    .line 15
    iget-wide v0, p5, Lg4/o0;->a:J

    .line 16
    .line 17
    invoke-static {v0, v1}, Lg4/o0;->f(J)I

    .line 18
    .line 19
    .line 20
    move-result p3

    .line 21
    iget-wide v0, p5, Lg4/o0;->a:J

    .line 22
    .line 23
    invoke-static {v0, v1}, Lg4/o0;->e(J)I

    .line 24
    .line 25
    .line 26
    move-result p5

    .line 27
    invoke-interface {p4, p3, p5}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 28
    .line 29
    .line 30
    move-result-object p3

    .line 31
    invoke-virtual {p3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p3

    .line 35
    new-instance p4, Landroid/content/Intent;

    .line 36
    .line 37
    invoke-direct {p4}, Landroid/content/Intent;-><init>()V

    .line 38
    .line 39
    .line 40
    const-string p5, "android.intent.action.PROCESS_TEXT"

    .line 41
    .line 42
    invoke-virtual {p4, p5}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 43
    .line 44
    .line 45
    move-result-object p4

    .line 46
    const-string p5, "text/plain"

    .line 47
    .line 48
    invoke-virtual {p4, p5}, Landroid/content/Intent;->setType(Ljava/lang/String;)Landroid/content/Intent;

    .line 49
    .line 50
    .line 51
    move-result-object p4

    .line 52
    const-string p5, "android.intent.extra.PROCESS_TEXT_READONLY"

    .line 53
    .line 54
    invoke-virtual {p4, p5, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    iget-object p2, p2, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    .line 59
    .line 60
    iget-object p4, p2, Landroid/content/pm/ActivityInfo;->packageName:Ljava/lang/String;

    .line 61
    .line 62
    iget-object p2, p2, Landroid/content/pm/ActivityInfo;->name:Ljava/lang/String;

    .line 63
    .line 64
    invoke-virtual {p0, p4, p2}, Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    const-string p2, "android.intent.extra.PROCESS_TEXT"

    .line 69
    .line 70
    invoke-virtual {p0, p2, p3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, p0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    .line 74
    .line 75
    .line 76
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0
.end method
