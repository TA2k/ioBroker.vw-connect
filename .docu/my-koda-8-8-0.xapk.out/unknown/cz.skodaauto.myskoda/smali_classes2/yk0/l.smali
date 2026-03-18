.class public final Lyk0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lal0/f0;
.implements Lme0/a;


# static fields
.field public static final b:Ljava/lang/Object;


# instance fields
.field public final a:Lyy0/c2;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lbl0/h0;->d:Lbl0/h0;

    .line 2
    .line 3
    sget-object v1, Lbl0/i0;->e:Lbl0/i0;

    .line 4
    .line 5
    new-instance v2, Llx0/l;

    .line 6
    .line 7
    invoke-direct {v2, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lbl0/h0;->h:Lbl0/h0;

    .line 11
    .line 12
    new-instance v3, Llx0/l;

    .line 13
    .line 14
    invoke-direct {v3, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    sget-object v0, Lbl0/h0;->i:Lbl0/h0;

    .line 18
    .line 19
    new-instance v4, Llx0/l;

    .line 20
    .line 21
    invoke-direct {v4, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    filled-new-array {v2, v3, v4}, [Llx0/l;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {v0}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lyk0/l;->b:Ljava/lang/Object;

    .line 33
    .line 34
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lyk0/l;->b:Ljava/lang/Object;

    .line 5
    .line 6
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lyk0/l;->a:Lyy0/c2;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lyk0/l;->a:Lyy0/c2;

    .line 2
    .line 3
    sget-object p1, Lyk0/l;->b:Ljava/lang/Object;

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
