.class public final Lh2/y4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lb71/o;

.field public final synthetic e:Z

.field public final synthetic f:Ll2/b1;


# direct methods
.method public constructor <init>(Lb71/o;ZLl2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/y4;->d:Lb71/o;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh2/y4;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh2/y4;->f:Ll2/b1;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Ln3/b;

    .line 2
    .line 3
    iget-object p1, p1, Ln3/b;->a:Landroid/view/KeyEvent;

    .line 4
    .line 5
    invoke-static {p1}, Ln3/c;->c(Landroid/view/KeyEvent;)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x1

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    invoke-static {p1}, Lh2/r;->A(Landroid/view/KeyEvent;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-static {v0}, Ljp/x1;->a(I)J

    .line 23
    .line 24
    .line 25
    move-result-wide v0

    .line 26
    sget-wide v2, Ln3/a;->j:J

    .line 27
    .line 28
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    :cond_0
    invoke-static {p1}, Lh2/r;->A(Landroid/view/KeyEvent;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    iget-object p0, p0, Lh2/y4;->d:Lb71/o;

    .line 41
    .line 42
    invoke-virtual {p0}, Lb71/o;->invoke()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_1
    iget-boolean v0, p0, Lh2/y4;->e:Z

    .line 49
    .line 50
    iget-object p0, p0, Lh2/y4;->f:Ll2/b1;

    .line 51
    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    invoke-static {v0}, Ljp/x1;->a(I)J

    .line 59
    .line 60
    .line 61
    move-result-wide v0

    .line 62
    sget-wide v2, Ln3/a;->i:J

    .line 63
    .line 64
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-nez v0, :cond_2

    .line 69
    .line 70
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    invoke-static {v0}, Ljp/x1;->a(I)J

    .line 75
    .line 76
    .line 77
    move-result-wide v0

    .line 78
    sget-wide v2, Ln3/a;->e:J

    .line 79
    .line 80
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-nez v0, :cond_2

    .line 85
    .line 86
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    invoke-static {p1}, Ljp/x1;->a(I)J

    .line 91
    .line 92
    .line 93
    move-result-wide v0

    .line 94
    sget-wide v2, Ln3/a;->d:J

    .line 95
    .line 96
    invoke-static {v0, v1, v2, v3}, Ln3/a;->a(JJ)Z

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    if-eqz p1, :cond_3

    .line 101
    .line 102
    :cond_2
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 103
    .line 104
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    return-object p1

    .line 108
    :cond_3
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 109
    .line 110
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    return-object p1
.end method
