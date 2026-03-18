.class public abstract Lka/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p2, p0, Lka/u;->a:I

    .line 3
    iput-object p1, p0, Lka/u;->b:Ljava/lang/Object;

    .line 4
    iput-object p3, p0, Lka/u;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lka/f0;)V
    .locals 1

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/high16 v0, -0x80000000

    .line 6
    iput v0, p0, Lka/u;->a:I

    .line 7
    new-instance v0, Landroid/graphics/Rect;

    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    iput-object v0, p0, Lka/u;->c:Ljava/lang/Object;

    .line 8
    iput-object p1, p0, Lka/u;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ls6/g;)V
    .locals 1

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 10
    iput v0, p0, Lka/u;->a:I

    .line 11
    new-instance v0, Ls6/c;

    invoke-direct {v0}, Ls6/c;-><init>()V

    iput-object v0, p0, Lka/u;->c:Ljava/lang/Object;

    .line 12
    iput-object p1, p0, Lka/u;->b:Ljava/lang/Object;

    return-void
.end method

.method public static b(Lka/f0;I)Lka/u;
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-ne p1, v0, :cond_0

    .line 5
    .line 6
    new-instance p1, Lka/t;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    invoke-direct {p1, p0, v0}, Lka/t;-><init>(Lka/f0;I)V

    .line 10
    .line 11
    .line 12
    return-object p1

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "invalid orientation"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0

    .line 21
    :cond_1
    new-instance p1, Lka/t;

    .line 22
    .line 23
    const/4 v0, 0x0

    .line 24
    invoke-direct {p1, p0, v0}, Lka/t;-><init>(Lka/f0;I)V

    .line 25
    .line 26
    .line 27
    return-object p1
.end method


# virtual methods
.method public abstract a(Lua/a;)V
.end method

.method public abstract c(Lua/a;)V
.end method

.method public abstract d(Landroid/view/View;)I
.end method

.method public abstract e(Landroid/view/View;)I
.end method

.method public abstract f(Landroid/view/View;)I
.end method

.method public abstract g(Landroid/view/View;)I
.end method

.method public abstract h()I
.end method

.method public abstract i()I
.end method

.method public abstract j()I
.end method

.method public abstract k()I
.end method

.method public abstract l()I
.end method

.method public abstract m()I
.end method

.method public abstract n()I
.end method

.method public abstract o(Landroid/view/View;)I
.end method

.method public abstract p(Landroid/view/View;)I
.end method

.method public abstract q(I)V
.end method

.method public abstract r(Lua/a;)V
.end method

.method public abstract s(Lua/a;)V
.end method

.method public abstract t(Lua/a;)V
.end method

.method public abstract u(Lua/a;)V
.end method

.method public abstract v(Lua/a;)Lco/a;
.end method
