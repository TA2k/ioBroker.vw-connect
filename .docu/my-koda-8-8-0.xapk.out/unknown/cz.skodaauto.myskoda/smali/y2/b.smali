.class public final Ly2/b;
.super Ly2/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lpv/g;

.field public final b:Ld4/s;

.field public final c:Lw3/t;

.field public final d:Le4/a;

.field public final e:Ljava/lang/String;

.field public final f:Landroid/graphics/Rect;

.field public final g:Landroid/view/autofill/AutofillId;

.field public final h:Landroidx/collection/c0;

.field public i:Z


# direct methods
.method public constructor <init>(Lpv/g;Ld4/s;Lw3/t;Le4/a;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly2/b;->a:Lpv/g;

    .line 5
    .line 6
    iput-object p2, p0, Ly2/b;->b:Ld4/s;

    .line 7
    .line 8
    iput-object p3, p0, Ly2/b;->c:Lw3/t;

    .line 9
    .line 10
    iput-object p4, p0, Ly2/b;->d:Le4/a;

    .line 11
    .line 12
    iput-object p5, p0, Ly2/b;->e:Ljava/lang/String;

    .line 13
    .line 14
    new-instance p1, Landroid/graphics/Rect;

    .line 15
    .line 16
    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Ly2/b;->f:Landroid/graphics/Rect;

    .line 20
    .line 21
    const/4 p1, 0x1

    .line 22
    invoke-virtual {p3, p1}, Landroid/view/View;->setImportantForAutofill(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p3}, Landroid/view/View;->getAutofillId()Landroid/view/autofill/AutofillId;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    iput-object p1, p0, Ly2/b;->g:Landroid/view/autofill/AutofillId;

    .line 32
    .line 33
    new-instance p1, Landroidx/collection/c0;

    .line 34
    .line 35
    invoke-direct {p1}, Landroidx/collection/c0;-><init>()V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Ly2/b;->h:Landroidx/collection/c0;

    .line 39
    .line 40
    return-void

    .line 41
    :cond_0
    const-string p0, "Required value was null."

    .line 42
    .line 43
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    throw p0
.end method
