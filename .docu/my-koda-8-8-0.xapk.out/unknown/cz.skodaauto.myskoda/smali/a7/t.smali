.class public final La7/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:La7/t;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, La7/t;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, La7/t;->a:La7/t;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Landroid/widget/RemoteViews;ILk7/g;)V
    .locals 2

    .line 1
    const-string p0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    const/16 v0, 0x1f

    .line 9
    .line 10
    const-string v1, "setClipToOutline"

    .line 11
    .line 12
    if-lt p0, v0, :cond_1

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    invoke-virtual {p1, p2, v1, p0}, Landroid/widget/RemoteViews;->setBoolean(ILjava/lang/String;Z)V

    .line 16
    .line 17
    .line 18
    instance-of v0, p3, Lk7/c;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    check-cast p3, Lk7/c;

    .line 23
    .line 24
    iget p3, p3, Lk7/c;->a:F

    .line 25
    .line 26
    invoke-virtual {p1, p2, p3, p0}, Landroid/widget/RemoteViews;->setViewOutlinePreferredRadius(IFI)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    new-instance p1, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string p2, "Rounded corners should not be "

    .line 35
    .line 36
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-virtual {p2}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string p1, " is only available on SDK "

    .line 71
    .line 72
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string p1, " and higher"

    .line 79
    .line 80
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p1
.end method

.method public final b(Landroid/widget/RemoteViews;ILk7/g;)V
    .locals 1

    .line 1
    instance-of p0, p3, Lk7/f;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    const/high16 p0, -0x40000000    # -2.0f

    .line 7
    .line 8
    invoke-virtual {p1, p2, p0, v0}, Landroid/widget/RemoteViews;->setViewLayoutHeight(IFI)V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    instance-of p0, p3, Lk7/d;

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    invoke-virtual {p1, p2, p0, v0}, Landroid/widget/RemoteViews;->setViewLayoutHeight(IFI)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    instance-of p0, p3, Lk7/c;

    .line 22
    .line 23
    if-eqz p0, :cond_2

    .line 24
    .line 25
    check-cast p3, Lk7/c;

    .line 26
    .line 27
    iget p0, p3, Lk7/c;->a:F

    .line 28
    .line 29
    const/4 p3, 0x1

    .line 30
    invoke-virtual {p1, p2, p0, p3}, Landroid/widget/RemoteViews;->setViewLayoutHeight(IFI)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    sget-object p0, Lk7/e;->a:Lk7/e;

    .line 35
    .line 36
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-eqz p0, :cond_3

    .line 41
    .line 42
    const/high16 p0, -0x40800000    # -1.0f

    .line 43
    .line 44
    invoke-virtual {p1, p2, p0, v0}, Landroid/widget/RemoteViews;->setViewLayoutHeight(IFI)V

    .line 45
    .line 46
    .line 47
    :goto_0
    return-void

    .line 48
    :cond_3
    new-instance p0, La8/r0;

    .line 49
    .line 50
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 51
    .line 52
    .line 53
    throw p0
.end method

.method public final c(Landroid/widget/RemoteViews;ILk7/g;)V
    .locals 1

    .line 1
    instance-of p0, p3, Lk7/f;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    const/high16 p0, -0x40000000    # -2.0f

    .line 7
    .line 8
    invoke-virtual {p1, p2, p0, v0}, Landroid/widget/RemoteViews;->setViewLayoutWidth(IFI)V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    instance-of p0, p3, Lk7/d;

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    invoke-virtual {p1, p2, p0, v0}, Landroid/widget/RemoteViews;->setViewLayoutWidth(IFI)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    instance-of p0, p3, Lk7/c;

    .line 22
    .line 23
    if-eqz p0, :cond_2

    .line 24
    .line 25
    check-cast p3, Lk7/c;

    .line 26
    .line 27
    iget p0, p3, Lk7/c;->a:F

    .line 28
    .line 29
    const/4 p3, 0x1

    .line 30
    invoke-virtual {p1, p2, p0, p3}, Landroid/widget/RemoteViews;->setViewLayoutWidth(IFI)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    sget-object p0, Lk7/e;->a:Lk7/e;

    .line 35
    .line 36
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-eqz p0, :cond_3

    .line 41
    .line 42
    const/high16 p0, -0x40800000    # -1.0f

    .line 43
    .line 44
    invoke-virtual {p1, p2, p0, v0}, Landroid/widget/RemoteViews;->setViewLayoutWidth(IFI)V

    .line 45
    .line 46
    .line 47
    :goto_0
    return-void

    .line 48
    :cond_3
    new-instance p0, La8/r0;

    .line 49
    .line 50
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 51
    .line 52
    .line 53
    throw p0
.end method
