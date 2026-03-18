.class public final Li70/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk70/x;
.implements Lme0/b;


# static fields
.field public static final i:Ll70/k;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lez0/c;

.field public final c:Lyy0/c2;

.field public final d:Lyy0/l1;

.field public e:Ljava/lang/String;

.field public final f:Lyy0/c2;

.field public final g:Lyy0/l1;

.field public h:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ll70/k;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ll70/k;-><init>(Ll70/b;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Li70/c;->i:Ll70/k;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lwe0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li70/c;->a:Lwe0/a;

    .line 5
    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Li70/c;->b:Lez0/c;

    .line 11
    .line 12
    sget-object p1, Li70/c;->i:Ll70/k;

    .line 13
    .line 14
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Li70/c;->c:Lyy0/c2;

    .line 19
    .line 20
    new-instance v0, Lyy0/l1;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Li70/c;->d:Lyy0/l1;

    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Li70/c;->f:Lyy0/c2;

    .line 33
    .line 34
    new-instance v0, Lyy0/l1;

    .line 35
    .line 36
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Li70/c;->g:Lyy0/l1;

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p0}, Li70/c;->b()V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Li70/c;->c:Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    sget-object v1, Li70/c;->i:Ll70/k;

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Li70/c;->b()V

    .line 16
    .line 17
    .line 18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-object v0, p0, Li70/c;->f:Lyy0/c2;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iput-object v1, p0, Li70/c;->e:Ljava/lang/String;

    .line 8
    .line 9
    iget-object p0, p0, Li70/c;->a:Lwe0/a;

    .line 10
    .line 11
    check-cast p0, Lwe0/c;

    .line 12
    .line 13
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 14
    .line 15
    .line 16
    return-void
.end method
