.class public final Lyk0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lal0/z;
.implements Lme0/a;


# static fields
.field public static final c:Lbl0/h;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lbl0/h;

    .line 2
    .line 3
    sget-object v1, Lbl0/e;->c:Lbl0/e;

    .line 4
    .line 5
    sget-object v1, Lbl0/e;->f:Lbl0/e;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 9
    .line 10
    move-object v4, v3

    .line 11
    move-object v5, v3

    .line 12
    invoke-direct/range {v0 .. v5}, Lbl0/h;-><init>(Lbl0/e;ZLjava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lyk0/a;->c:Lbl0/h;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lyk0/a;->c:Lbl0/h;

    .line 5
    .line 6
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lyk0/a;->a:Lyy0/c2;

    .line 11
    .line 12
    new-instance v1, Lyy0/l1;

    .line 13
    .line 14
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 15
    .line 16
    .line 17
    iput-object v1, p0, Lyk0/a;->b:Lyy0/l1;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lyk0/a;->a:Lyy0/c2;

    .line 2
    .line 3
    sget-object p1, Lyk0/a;->c:Lbl0/h;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    return-object p0
.end method
