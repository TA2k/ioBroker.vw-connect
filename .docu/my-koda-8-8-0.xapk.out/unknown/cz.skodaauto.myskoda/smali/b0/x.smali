.class public final Lb0/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk0/c;


# static fields
.field public static final g:Lb0/x;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/high16 v0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    new-instance v2, Lc6/b;

    .line 13
    .line 14
    invoke-direct {v2, v1, v1}, Lc6/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Lc6/b;

    .line 18
    .line 19
    invoke-direct {v1, v0, v0}, Lc6/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance v0, Lb0/x;

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    invoke-direct {v0, v3, v2, v1}, Lb0/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Lb0/x;->g:Lb0/x;

    .line 29
    .line 30
    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lb0/x;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lb0/x;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lb0/x;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public c(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Lb0/x;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Void;

    .line 7
    .line 8
    iget-object p1, p0, Lb0/x;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Lc6/a;

    .line 11
    .line 12
    iget-object p0, p0, Lb0/x;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Landroid/view/Surface;

    .line 15
    .line 16
    new-instance v0, Lb0/i;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-direct {v0, v1, p0}, Lb0/i;-><init>(ILandroid/view/Surface;)V

    .line 20
    .line 21
    .line 22
    invoke-interface {p1, v0}, Lc6/a;->accept(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_0
    check-cast p1, Ljava/lang/Void;

    .line 27
    .line 28
    iget-object p0, p0, Lb0/x;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Ly4/h;

    .line 31
    .line 32
    const/4 p1, 0x0

    .line 33
    invoke-virtual {p0, p1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    invoke-static {p1, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    iget v0, p0, Lb0/x;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lb0/v1;

    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "Camera surface session should only fail with request cancellation. Instead failed due to:\n"

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-static {p1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 23
    .line 24
    .line 25
    iget-object p1, p0, Lb0/x;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Lc6/a;

    .line 28
    .line 29
    iget-object p0, p0, Lb0/x;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Landroid/view/Surface;

    .line 32
    .line 33
    new-instance v0, Lb0/i;

    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    invoke-direct {v0, v1, p0}, Lb0/i;-><init>(ILandroid/view/Surface;)V

    .line 37
    .line 38
    .line 39
    invoke-interface {p1, v0}, Lc6/a;->accept(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :pswitch_0
    instance-of p1, p1, Lb0/v1;

    .line 44
    .line 45
    const/4 v0, 0x0

    .line 46
    if-eqz p1, :cond_0

    .line 47
    .line 48
    iget-object p0, p0, Lb0/x;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Ly4/k;

    .line 51
    .line 52
    const/4 p1, 0x0

    .line 53
    invoke-virtual {p0, p1}, Ly4/k;->cancel(Z)Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-static {v0, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    iget-object p0, p0, Lb0/x;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Ly4/h;

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    invoke-static {v0, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 70
    .line 71
    .line 72
    :goto_0
    return-void

    .line 73
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
