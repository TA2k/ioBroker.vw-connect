.class public final Lo30/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lo30/c;

.field public final b:Lo30/i;


# direct methods
.method public constructor <init>(Lo30/c;Lo30/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo30/n;->a:Lo30/c;

    .line 5
    .line 6
    iput-object p2, p0, Lo30/n;->b:Lo30/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    iget-object p2, p0, Lo30/n;->a:Lo30/c;

    .line 4
    .line 5
    invoke-virtual {p2, p1}, Lo30/c;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    new-instance v0, Lnz/g;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x2

    .line 13
    invoke-direct {v0, v2, p0, p1, v1}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lne0/n;

    .line 17
    .line 18
    invoke-direct {p0, v0, p2}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method
