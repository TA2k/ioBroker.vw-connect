.class public final enum Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "a"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a$a;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;",
        ">;"
    }
.end annotation


# static fields
.field public static final c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a$a;

.field public static final enum d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

.field public static final enum e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

.field public static final enum f:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

.field public static final enum g:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

.field public static final enum h:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

.field public static final enum i:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

.field private static final synthetic j:[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

.field private static final synthetic k:Lsx0/a;


# instance fields
.field private final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 2
    .line 3
    const-string v1, "INBOX_NO_URL"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 12
    .line 13
    const-string v1, "ALERT_INBOX_NO_URL"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 22
    .line 23
    const-string v1, "INBOX_CLOUDPAGE"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->f:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 30
    .line 31
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 32
    .line 33
    const-string v1, "ALERT_INBOX_CLOUDPAGE"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->g:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 40
    .line 41
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 42
    .line 43
    const-string v1, "INBOX_NON_CLOUDPAGE"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->h:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 50
    .line 51
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 52
    .line 53
    const-string v1, "ALERT_INBOX_NON_CLOUDPAGE"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;-><init>(Ljava/lang/String;II)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->i:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 60
    .line 61
    invoke-static {}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->a()[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->j:[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->k:Lsx0/a;

    .line 72
    .line 73
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a$a;

    .line 74
    .line 75
    const/4 v1, 0x0

    .line 76
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a$a;

    .line 80
    .line 81
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->b:I

    .line 5
    .line 6
    return-void
.end method

.method private static final synthetic a()[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;
    .locals 6

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->f:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->g:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 8
    .line 9
    sget-object v4, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->h:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 10
    .line 11
    sget-object v5, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->i:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    return-object v0
.end method

.method public static b()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->k:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->j:[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->b:I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
