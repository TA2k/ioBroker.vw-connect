.class public final Lsk0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luk0/v;
.implements Lme0/a;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lsk0/b;->a:Lyy0/c2;

    .line 10
    .line 11
    new-instance v1, Lyy0/l1;

    .line 12
    .line 13
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lsk0/b;->b:Lyy0/l1;

    .line 17
    .line 18
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 19
    .line 20
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Lsk0/b;->c:Lyy0/c2;

    .line 25
    .line 26
    new-instance v1, Lyy0/l1;

    .line 27
    .line 28
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 29
    .line 30
    .line 31
    iput-object v1, p0, Lsk0/b;->d:Lyy0/l1;

    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lsk0/b;->a:Lyy0/c2;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    return-object p0
.end method
