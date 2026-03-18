.class public final Lwl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwl/f;


# instance fields
.field public final a:Ljl/i;

.field public final b:Ltl/i;

.field public final c:I


# direct methods
.method public constructor <init>(Ljl/i;Ltl/i;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwl/b;->a:Ljl/i;

    .line 5
    .line 6
    iput-object p2, p0, Lwl/b;->b:Ltl/i;

    .line 7
    .line 8
    iput p3, p0, Lwl/b;->c:I

    .line 9
    .line 10
    if-lez p3, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "durationMillis must be > 0."

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method


# virtual methods
.method public final a()V
    .locals 5

    .line 1
    new-instance v0, Lml/a;

    .line 2
    .line 3
    iget-object v1, p0, Lwl/b;->a:Ljl/i;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lwl/b;->b:Ltl/i;

    .line 9
    .line 10
    invoke-virtual {v1}, Ltl/i;->a()Landroid/graphics/drawable/Drawable;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v1}, Ltl/i;->b()Ltl/h;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    iget-object v3, v3, Ltl/h;->w:Lul/f;

    .line 19
    .line 20
    instance-of v4, v1, Ltl/n;

    .line 21
    .line 22
    if-eqz v4, :cond_1

    .line 23
    .line 24
    check-cast v1, Ltl/n;

    .line 25
    .line 26
    iget-boolean v1, v1, Ltl/n;->g:Z

    .line 27
    .line 28
    if-nez v1, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v1, 0x0

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    :goto_0
    const/4 v1, 0x1

    .line 34
    :goto_1
    iget p0, p0, Lwl/b;->c:I

    .line 35
    .line 36
    invoke-direct {v0, v2, v3, p0, v1}, Lml/a;-><init>(Landroid/graphics/drawable/Drawable;Lul/f;IZ)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
