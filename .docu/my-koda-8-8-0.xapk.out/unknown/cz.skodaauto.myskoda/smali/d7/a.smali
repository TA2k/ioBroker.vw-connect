.class public final Ld7/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ld7/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ld7/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ld7/a;->a:Ld7/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(La7/e2;Landroid/widget/RemoteViews;Lk7/a;I)V
    .locals 4

    .line 1
    instance-of p0, p3, Le7/a;

    .line 2
    .line 3
    const-string v0, "setColorFilter"

    .line 4
    .line 5
    const-string v1, "<this>"

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    check-cast p3, Le7/a;

    .line 10
    .line 11
    iget-wide p0, p3, Le7/a;->a:J

    .line 12
    .line 13
    iget-wide v2, p3, Le7/a;->b:J

    .line 14
    .line 15
    invoke-static {p0, p1}, Le3/j0;->z(J)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {v2, v3}, Le3/j0;->z(J)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-static {p2, p4, v0, p0, p1}, Lh6/h;->f(Landroid/widget/RemoteViews;ILjava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    instance-of p0, p3, Lk7/i;

    .line 31
    .line 32
    if-eqz p0, :cond_1

    .line 33
    .line 34
    check-cast p3, Lk7/i;

    .line 35
    .line 36
    iget p0, p3, Lk7/i;->a:I

    .line 37
    .line 38
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {p2, p4, v0, p0}, Lh6/h;->d(Landroid/widget/RemoteViews;ILjava/lang/String;I)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_1
    iget-object p0, p1, La7/e2;->a:Landroid/content/Context;

    .line 46
    .line 47
    invoke-interface {p3, p0}, Lk7/a;->a(Landroid/content/Context;)J

    .line 48
    .line 49
    .line 50
    move-result-wide p0

    .line 51
    invoke-static {p0, p1}, Le3/j0;->z(J)I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p2, p4, v0, p0}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 59
    .line 60
    .line 61
    return-void
.end method
