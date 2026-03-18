.class public final Le2/m;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ljava/lang/CharSequence;

.field public e:Ljava/lang/Object;

.field public f:Lez0/c;

.field public g:J

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Le2/o;

.field public j:I


# direct methods
.method public constructor <init>(Le2/o;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Le2/m;->i:Le2/o;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iput-object p1, p0, Le2/m;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Le2/m;->j:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Le2/m;->j:I

    .line 9
    .line 10
    const-wide/16 v2, 0x0

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    iget-object v0, p0, Le2/m;->i:Le2/o;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    move-object v5, p0

    .line 17
    invoke-static/range {v0 .. v5}, Le2/o;->a(Le2/o;Ljava/lang/CharSequence;JLandroid/view/textclassifier/TextClassifier;Lrx0/c;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
